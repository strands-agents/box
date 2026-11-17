use dogwood_language::{Event, EventBuilder, Value};
use dogwood_local_engine::{Clock, DurableConfig, DurableLog, DurableTemporalEngine, Outcome, Record, SnapshotPayload, Write};
use serde_json::{json, Value as Json};
use std::{env, path::Path, time::Duration};
type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
const NOW: i64 = 1_800_000_000_000_000_000;
const POLICY: &str = r#"
@id("allow_login")
permit(principal, action == Drupe::Action::"Login", resource);
@id("allow_read")
permit(principal, action == Drupe::Action::"Read", resource);
@id("deny_read_after_login")
forbid(principal, action == Drupe::Action::"Read", resource)
when { context has input.user }
when temporal {
  (count for (t: Timepoint). where (formerly within 1h (
    Drupe::Action::"Login"::response{ input.user: context.input.user } && tp(t)
  ))) >= context.input.threshold
};
"#;
const SCHEMA: &str = r#"
namespace Drupe {
  type LoginInput = { user: String };
  type ReadInput = { user: String, threshold: Long };
  entity Gateway;
  entity OAuthUser = { id: String } tags String;
  action "Login" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: LoginInput }
  };
  action "Read" appliesTo {
    principal: [OAuthUser], resource: [Gateway], context: { input: ReadInput }
  };
}
"#;
struct FixedClock;
impl Clock for FixedClock { fn now_nanos(&self) -> i64 { NOW } }
fn open(path: &Path) -> Result<DurableTemporalEngine> {
  Ok(DurableTemporalEngine::open_with_config(path,
    DurableConfig::new(0).with_clock(Box::new(FixedClock))
      .with_max_future_skew(Duration::MAX)).map_err(|e|e.to_string())?)
}
fn event(action: &str, kind: &str) -> EventBuilder {
  Event::builder(action, kind)
    .principal("Drupe::OAuthUser::\"alice\"")
    .resource("Drupe::Gateway::\"gw1\"")
    .field("input", "user", Value::String("alice".into()))
    .request_context("input", "user", Value::String("alice".into()))
}
fn read_limit(engine: &mut DurableTemporalEngine, threshold: i64) -> Result<Json> {
  let r=engine.submit(event("Drupe::Action::Read", "request")
    .field("input", "threshold", Value::Int(threshold))
    .request_context("input", "threshold", Value::Int(threshold))).map_err(|e|e.to_string())?;
  match r.outcome {
    Outcome::Decision(d) => Ok(json!({"allowed":d.allowed(),"offset":r.offset,"timestamp":r.ts,"threshold":threshold})),
    Outcome::Recorded => Err("read request produced no decision".into()),
  }
}
fn raw(path: &Path) -> Result<Json> {
  let log=DurableLog::open(path)?;
  let snapshot=log.get_snapshot()?.map(|s|json!({"up_to_offset":s.up_to_offset,"payload_bytes":s.payload.len(),"payload_hex":s.payload.iter().map(|b|format!("{b:02x}")).collect::<String>()}));
  let mut records=Vec::new();
  let mut decode_errors=Vec::new();
  log.scan_from(log.base_offset(), |offset, bytes| {
    let decoded=match Record::decode(bytes) {
      Ok(Record::Event(e))=>json!({"event":dogwood_local_engine::event_to_json(&e)}),
      Ok(r)=>json!({"control":format!("{r:?}")}),
      Err(e)=>{ decode_errors.push(e.to_string()); json!(null) }
    };
    records.push(json!({"offset":offset,"raw_hex":bytes.iter().map(|b|format!("{b:02x}")).collect::<String>(),"decoded":decoded}));
  })?;
  Ok(json!({"base_offset":log.base_offset(),"next_offset":log.next_offset(),"snapshot":snapshot,"records":records,"decode_errors":decode_errors}))
}
fn run(args: &[String]) -> Result<Json> {
  let mode=args.get(1).ok_or("mode missing")?;
  let path=Path::new(args.get(2).ok_or("path missing")?);
  if mode=="inspect" { return raw(path); }
  if mode=="migrate" {return migrate(path,Path::new(args.get(3).ok_or("destination missing")?));}
  let before=if path.exists(){Some(raw(path)?)}else{None};
  let mut engine=match open(path) {
    Ok(e)=>e,
    Err(e)=>return Ok(json!({"ok":false,"stage":"DurableTemporalEngine::open_with_config/recovery","error":e.to_string(),"before":before,"after":raw(path)?})),
  };
  if mode=="progress" || mode=="verify-three" {
    let policies=engine.list();
    let mut decisions=Vec::new();
    if mode=="progress" {
      let two=read_limit(&mut engine,2)?; assert_eq!(two["allowed"],false); decisions.push(two);
      let three=read_limit(&mut engine,3)?; assert_eq!(three["allowed"],true); decisions.push(three);
      let new_event=engine.submit(event("Drupe::Action::Login","response")).map_err(|e|e.to_string())?;
      assert!(matches!(new_event.outcome,Outcome::Recorded));
    }
    let three=read_limit(&mut engine,3)?; assert_eq!(three["allowed"],false,"two old plus one new Login responses must count"); decisions.push(three);
    let four=read_limit(&mut engine,4)?; assert_eq!(four["allowed"],true,"must have exactly three Login responses"); decisions.push(four);
    let checkpoint=if mode=="progress"{Some(engine.checkpoint().map_err(|e|e.to_string())?)}else{None};
    assert_eq!(policies,engine.list(),"decisions/checkpoint must not alter installed policy identities");
    drop(engine);
    return Ok(json!({"ok":true,"stage":mode,"policies":policies,"decisions":decisions,"checkpoint":checkpoint,"before":before,"after":raw(path)?}));
  }
  if mode=="reopen" {
    let policies=engine.list();
    let d=read_limit(&mut engine,2)?;
    assert_eq!(d["allowed"],false,"recovered login must keep Read denied");
    let after_policies=engine.list();
    drop(engine);
    return Ok(json!({"ok":true,"stage":"recovered_and_decided","policies":policies,"policies_after":after_policies,"decision":d,"before":before,"after":raw(path)?}));
  }
  assert_eq!(mode,"seed");
  assert!(!engine.has_policy(),"seed path must be new");
  let storage=args.get(3).ok_or("storage mode missing")?;
  let fixture=args.get(4).ok_or("fixture missing")?;
  let source=if fixture=="dotted-has"{POLICY.to_string()}else{assert_eq!(fixture,"plain-control");POLICY.replace("when { context has input.user }\n", "")};
  if let Err(e)=engine.install(&source,SCHEMA,None,None){return Ok(json!({"ok":false,"stage":"install","error":e.to_string(),"source":source}));}
  let before_login=read_limit(&mut engine,2)?;
  assert_eq!(before_login["allowed"],true,"before Login, Read must be allowed");
  let login=engine.submit(event("Drupe::Action::Login","request")).map_err(|e|e.to_string())?;
  assert!(matches!(login.outcome,Outcome::Decision(d) if d.allowed()));
  let response=engine.submit(event("Drupe::Action::Login","response")).map_err(|e|e.to_string())?;
  assert!(matches!(response.outcome,Outcome::Recorded));
  let second=engine.submit(event("Drupe::Action::Login","response")).map_err(|e|e.to_string())?;
  assert!(matches!(second.outcome,Outcome::Recorded));
  let after_login=read_limit(&mut engine,2)?;
  assert_eq!(after_login["allowed"],false,"recorded Login must make Read denied");
  let checkpoint=if storage=="pruned" {Some(engine.checkpoint().map_err(|e|e.to_string())?)}else{assert_eq!(storage,"complete");None};
  let tail=if checkpoint.is_some(){let d=read_limit(&mut engine,2)?;assert_eq!(d["allowed"],false);Some(d)}else{None};
  let policies=engine.list();
  let status=engine.status();
  drop(engine);
  let after=raw(path)?;
  if storage=="pruned" {assert!(after["base_offset"].as_u64().unwrap()>0,"must actually prune");assert!(after["records"].as_array().unwrap().len()>0,"retain a suffix after snapshot");}
  else {assert_eq!(after["base_offset"],0);assert!(after["snapshot"].is_null());}
  Ok(json!({"ok":true,"stage":"seeded_and_closed","fixture":fixture,"storage":storage,"authored_policy":source,"schema":SCHEMA,"clock_nanos":NOW,"before_login":before_login,"after_login":after_login,"checkpoint":checkpoint,"tail":tail,"policies":policies,"rule_count":status.rule_count,"leaf_count":status.leaf_count,"after":after}))
}

fn hex(bytes:&[u8])->String{bytes.iter().map(|b|format!("{b:02x}")).collect()}
fn rewritten(statement:&str)->Option<String>{
  if !statement.contains("has \"input\".user"){return None;}
  assert!(statement.contains("deny_read_after_login"));
  assert_eq!(statement.matches("has \"input\".user").count(),1);
  Some(statement.replace("has \"input\".user","has input.user"))
}
fn migrate(source:&Path,dest:&Path)->Result<Json>{
  assert!(source.exists()&&!dest.exists());
  let log=DurableLog::open(source)?;
  let base=log.base_offset();let next=log.next_offset();
  let snapshot=log.get_snapshot()?;
  let keys=["dogwood_server_time_unit","dogwood_server_service_schema"];
  let metadata=keys.iter().map(|k|Ok((*k,log.get_meta(k)?))).collect::<Result<Vec<_>>>()?;
  let mut records=Vec::new();log.scan_from(base,|o,b|records.push((o,b.to_vec())))?;
  drop(log);
  let mut changed=0;
  let mut changed_records=Vec::new();
  let mut snapshot_evidence=json!(null);
  if base==0 {
    assert!(snapshot.is_none(),"this bounded full-log control expects no snapshot");
    let out=DurableLog::open(dest)?;
    for (key,value) in &metadata {if let Some(value)=value{out.commit(&[Write::Meta{key,value}])?;}}
    for (offset,bytes) in &records {
      let mut r=Record::decode(bytes)?;
      let original_debug=format!("{r:?}");
      let mut updated=false;
      match &mut r {
        Record::Add{statement,..}|Record::Update{statement,..}=>{
          if let Some(replacement)=rewritten(statement){*statement=replacement;updated=true;changed+=1;}
        },_=>()
      }
      let output=if updated{r.encode()}else{bytes.clone()};
      if updated{changed_records.push(json!({"offset":offset,"before":original_debug,"after":format!("{r:?}"),"before_hex":hex(bytes),"after_hex":hex(&output)}));}
      assert_eq!(out.append(&output)?,*offset);
    }
    assert_eq!(out.next_offset(),next);assert_eq!(out.base_offset(),0);
  } else {
    for (_,bytes) in &records {
      match Record::decode(bytes)? {
        Record::Add{statement,..}|Record::Update{statement,..}=>assert!(rewritten(&statement).is_none(),"unsupported incompatible control in tail"),_=>()
      }
    }
    let mut snapshot=snapshot.ok_or("pruned input has no snapshot")?;
    let mut payload=SnapshotPayload::decode(&snapshot.payload)?;
    let original_engine=payload.engine.clone();
    let original_ts=payload.last_ts;
    let original_schema=payload.bundle.action_schema.clone();
    let original_next_id=payload.bundle.policies.next_id();
    let original_entries=payload.bundle.policies.entries().cloned().collect::<Vec<_>>();
    for entry in &original_entries {
      if let Some(replacement)=rewritten(&entry.statement){
        assert!(payload.bundle.policies.update_statement(entry.id,replacement,entry.updated));changed+=1;
      }
    }
    let new_entries=payload.bundle.policies.entries().cloned().collect::<Vec<_>>();
    assert_eq!(original_entries.len(),new_entries.len());
    for (old,new) in original_entries.iter().zip(&new_entries){assert_eq!((&old.id,&old.token,old.created,old.updated),(&new.id,&new.token,new.created,new.updated));}
    assert_eq!(payload.engine,original_engine);assert_eq!(payload.last_ts,original_ts);assert_eq!(payload.bundle.action_schema,original_schema);assert_eq!(payload.bundle.policies.next_id(),original_next_id);
    snapshot_evidence=json!({"engine_bytes_unchanged":true,"engine_hex_before":hex(&original_engine),"engine_hex_after":hex(&payload.engine),"last_ts":original_ts,"next_policy_id":original_next_id,"entries_before":original_entries,"entries_after":new_entries});
    snapshot.payload=payload.encode()?;
    let decoded=SnapshotPayload::decode(&snapshot.payload)?;assert_eq!(decoded.engine,original_engine);assert_eq!(decoded.last_ts,original_ts);
    std::fs::copy(source,dest)?;
    let out=DurableLog::open(dest)?;out.commit(&[Write::Snapshot(&snapshot)])?;
    assert_eq!(out.base_offset(),base);assert_eq!(out.next_offset(),next);
  }
  assert_eq!(changed,1,"exactly the fixture's one saved static has guard must change");
  let after=raw(dest)?;
  let before=raw(source)?;
  if base>0{assert_eq!(before["records"],after["records"],"pruned suffix stays byte-identical");}
  let out=DurableLog::open(dest)?;
  for (key,value) in &metadata{assert_eq!(out.get_meta(key)?,*value);}
  drop(out);
  Ok(json!({"ok":true,"stage":"fixture_only_transformed_copy","changed":changed,"base_offset":base,"next_offset":next,"metadata":metadata.iter().map(|(k,v)|json!({"key":k,"value_hex":v.as_ref().map(|b|hex(b))})).collect::<Vec<_>>(),"changed_records":changed_records,"snapshot_preservation":snapshot_evidence,"before":before,"after":after}))
}

fn main(){
  let args=env::args().collect::<Vec<_>>();
  match run(&args) {
    Ok(mut x)=>{x["declared_dependency_version"]=json!(env!("CARGO_PKG_VERSION"));println!("{}",serde_json::to_string(&x).unwrap());if x["ok"]==false{std::process::exit(20);}},
    Err(e)=>{println!("{}",json!({"ok":false,"stage":"harness","error":e.to_string()}));std::process::exit(21);}
  }
}
