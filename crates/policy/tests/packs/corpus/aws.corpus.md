# aws pack corpus

Each row is one command line, and what the shell grammar of `../valid/aws.pack.toml` reads
it as. `Fields` lists, in TOML, each field that does not hold its default: a Bool `false`, an
empty set, or an absent string. `—` means none. An `unmodeled` row has no fields and no effects.
Rows marked "verified" were checked against aws-cli 2.36.

| Command line | Action | Fields | Effects | Note |
|---|---|---|---|---|
| `aws sts get-caller-identity` | sts_get_caller_identity | — | read_only |  |
| `aws --profile prod sts get-caller-identity` | sts_get_caller_identity | profile = "prod" | read_only |  |
| `aws sts get-caller-identity --profile=prod --region us-east-1 --output json` | sts_get_caller_identity | output = "json", profile = "prod", region = "us-east-1" | read_only | Global options after the operation |
| `aws sts get-caller-identity --query Account --output text` | sts_get_caller_identity | output = "text", query = "Account" | read_only |  |
| `aws s3 --region us-west-2 ls` | s3_ls | region = "us-west-2" | read_only | A global between the two command words (verified) |
| `aws s3 rm s3://logs/2026/app.log` | s3_rm | path = "s3://logs/2026/app.log" | delete_data |  |
| `aws s3 rm s3://logs/ --recursive --dryrun` | s3_rm | dryrun = true, path = "s3://logs/", recursive = true | — |  |
| `aws s3 rm s3://logs/ --recursive --dry` | unmodeled | — | — | Aws reads `--dry` as `--dryrun` (verified); no prefix matching |
| `aws s3 rm --profile=prod s3://logs/k` | s3_rm | path = "s3://logs/k", profile = "prod" | delete_data |  |
| `aws s3 rm --exclude '*' --include '*.log' --recursive s3://logs/` | s3_rm | exclude = ["*"], include = ["*.log"], path = "s3://logs/", recursive = true | delete_data |  |
| `aws s3 rm` | unmodeled | — | — | Required operand `<path>` missing |
| `aws s3 rm help` | s3_rm | path = "help" | delete_data | Aws prints help instead; over-restriction, harmless |
| `aws s3 cp ./site s3://www/ --recursive --acl public-read` | s3_cp | acl = "public-read", destination = "s3://www/", recursive = true, source = "./site" | make_public, write_data |  |
| `aws s3 cp s3://data/dump.sql .` | s3_cp | destination = ".", source = "s3://data/dump.sql" | read_data |  |
| `aws s3 cp s3://a/x s3://b/x` | s3_cp | destination = "s3://b/x", source = "s3://a/x" | read_data, write_data |  |
| `aws s3 cp - s3://b/k` | s3_cp | destination = "s3://b/k", source = "-" | write_data | Standard input: a lone `-` is an operand |
| `aws s3 cp a s3://b/ --grants read=uri=http://acs.amazonaws.com/groups/global/AllUsers` | s3_cp | destination = "s3://b/", grants = ["read=uri=http://acs.amazonaws.com/groups/global/AllUsers"], source = "a" | make_public, write_data | A `many` value, and `like` on an option |
| `aws s3 cp --sse AES256 a s3://b/` | unmodeled | — | — | The pack leaves out `--sse`, because its optional value takes the next word in aws |
| `aws s3 mv s3://a/x ./x` | s3_mv | destination = "./x", source = "s3://a/x" | delete_data, read_data |  |
| `aws s3 mv ./x s3://a/x` | s3_mv | destination = "s3://a/x", source = "./x" | delete_data, write_data |  |
| `aws s3 sync . s3://site --delete` | s3_sync | delete = true, destination = "s3://site", source = "." | delete_data, write_data |  |
| `aws s3 sync s3://site ./local --delete --dryrun` | s3_sync | delete = true, destination = "./local", dryrun = true, source = "s3://site" | — |  |
| `aws s3 rb s3://old --force` | s3_rb | force = true, path = "s3://old" | delete_data |  |
| `aws s3api delete-bucket --bucket prod-logs` | s3api_delete_bucket | bucket = "prod-logs" | delete_data |  |
| `aws s3api delete-bucket --bucket=prod-logs --region eu-west-1` | s3api_delete_bucket | bucket = "prod-logs", region = "eu-west-1" | delete_data |  |
| `aws s3api delete-bucket --bucket file://name.txt` | s3api_delete_bucket | bucket = "file://name.txt" | delete_data | Aws reads the value from the file, and the parser sees only the name (L1) |
| `aws s3api delete-bucket --cli-input-json file://in.json` | unmodeled | — | — | `--cli-input-json` not declared |
| `aws s3api delete-bucket --bucket a --bucket b` | unmodeled | — | — | Non-repeated option given twice (argparse: last wins) |
| `aws s3api delete-bucket` | s3api_delete_bucket | — | delete_data | Aws refuses the line; required options are not checked |
| `aws ec2 terminate-instances --instance-ids i-1 i-2 --dry-run` | ec2_terminate_instances | dry_run = true, instance_ids = ["i-1", "i-2"] | — |  |
| `aws ec2 terminate-instances --instance-ids i-1 i-2` | ec2_terminate_instances | instance_ids = ["i-1", "i-2"] | terminate_compute |  |
| `aws ec2 terminate-instances --instance-ids=i-1 i-2` | unmodeled | — | — | `=` gives `many` exactly one value; `i-2` is then a stray operand |
| `aws ec2 terminate-instances --instance-ids i-1 --dry-run --no-dry-run` | unmodeled | — | — | Negation not declared (aws: last wins, so it would terminate) |
| `aws ec2 describe-instances --filters Name=tag:env,Values=prod --max-items 10` | ec2_describe_instances | filters = ["Name=tag:env,Values=prod"], max_items = "10" | read_only |  |
| `aws ec2 describe-instances --max-items ten` | ec2_describe_instances | max_items = "ten" | read_only | A string: the parser does not check that the value is a number |
| `aws sts assume-role --role-arn arn:aws:iam::1:role/admin --role-session-name s --duration-seconds 3600` | sts_assume_role | duration_seconds = "3600", role_arn = "arn:aws:iam::1:role/admin", role_session_name = "s" | assume_role |  |
| `aws iam list-roles --path-prefix /service/` | iam_list_roles | path_prefix = "/service/" | read_only |  |
| `aws iam create-access-key --user-name ci-bot` | iam_create_access_key | user_name = "ci-bot" | create_credentials, modify_iam |  |
| `aws iam attach-role-policy --role-name app --policy-arn arn:aws:iam::aws:policy/AdministratorAccess` | iam_attach_role_policy | policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess", role_name = "app" | modify_iam |  |
| `aws iam put-role-policy --role-name app --policy-name inline --policy-document file://p.json` | iam_put_role_policy | policy_document = "file://p.json", policy_name = "inline", role_name = "app" | modify_iam | The parser sees the file name only |
| `aws cloudformation delete-stack --stack-name prod-api --retain-resources DataBucket Logs` | cloudformation_delete_stack | retain_resources = ["DataBucket", "Logs"], stack_name = "prod-api" | delete_data, delete_infrastructure |  |
| `aws lambda invoke --function-name fn --payload file://e.json out.json` | lambda_invoke | function_name = "fn", outfile = "out.json", payload = "file://e.json" | invoke_function |  |
| `aws lambda invoke --function-name fn --invocation-type DryRun out.json` | lambda_invoke | function_name = "fn", invocation_type = "DryRun", outfile = "out.json" | — |  |
| `aws lambda invoke --function-name fn` | unmodeled | — | — | Required operand `<outfile>` missing |
| `aws --endpoint-url https://collector.example s3 ls` | s3_ls | endpoint_url = "https://collector.example" | custom_endpoint, read_only |  |
| `aws s3 ls --no-verify-ssl` | s3_ls | no_verify_ssl = true | insecure_tls, read_only |  |
| `aws --cli-auto-prompt s3 rm s3://b/k` | unmodeled | — | — | Interactive edit before run; not declared |
| `aws S3 ls` | unmodeled | — | — | Command words are case-sensitive (aws: "invalid choice") |
| `aws dynamodb delete-table --table-name t` | unmodeled | — | — | The pack does not declare this operation |
| `aws configure set region us-east-1` | unmodeled | — | — | The pack does not declare this operation |
| `aws s3 rm s3://b/k --profile` | unmodeled | — | — | The value is missing |
| `aws s3 cp a s3://b/ --grants` | unmodeled | — | — | A `many` value with no words |
