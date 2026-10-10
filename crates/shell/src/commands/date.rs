// Modified by Amazon. Original source: https://github.com/strands-agents/shell
// Local changes are recorded in crates/shell/UPSTREAM.md.

use crate::prelude::*;

const HELP: &str = "Usage: date [+FORMAT]
Display the current date and time.

Format specifiers:
  %Y  year (4 digits)
  %m  month (01-12)
  %d  day (01-31)
  %H  hour (00-23)
  %M  minute (00-59)
  %S  second (00-59)
  %a  weekday name (Sun-Sat)
  %b  month name (Jan-Dec)
  %c  default format

Options:
  -u  use UTC time
  -h  display this help";

#[command("date")]
async fn cmd_date(os: &Mediated, args: &[String]) -> CommandResult {
    let mut parser = lexopt::Parser::from_args(args);
    let mut _utc = false;
    let mut format = String::new();

    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                let mut w = io::stdout()?;
                wprintln!(w, "{}", HELP)?;
                return Ok(0);
            }
            Short('u') => _utc = true,
            Value(val) => {
                let s = val.string()?;
                if let Some(fmt) = s.strip_prefix('+') {
                    format = fmt.to_string();
                } else {
                    return Err(format!("date: invalid argument: {}", s).into());
                }
            }
            _ => return Err(arg.unexpected().into()),
        }
    }

    let now = os.now();
    let ts = now
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    // Convert to date components (UTC)
    let days = ts / 86400;
    let secs = ts % 86400;
    let hour = secs / 3600;
    let min = (secs % 3600) / 60;
    let sec = secs % 60;

    let (year, month, day) = {
        let mut y = 1970i64;
        let mut d = days;
        loop {
            let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
            let days_in_year = if leap { 366 } else { 365 };
            if d < days_in_year {
                break;
            }
            d -= days_in_year;
            y += 1;
        }
        let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
        let mdays = [
            31,
            if leap { 29 } else { 28 },
            31,
            30,
            31,
            30,
            31,
            31,
            30,
            31,
            30,
            31,
        ];
        let mut m = 0;
        for md in mdays {
            if d < md {
                break;
            }
            d -= md;
            m += 1;
        }
        (y, m + 1, d + 1)
    };

    let wday = ((days + 4) % 7) as usize;
    let wday_names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    let month_names = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];

    let fmt = if format.is_empty() { "%c" } else { &format };
    let mut result = String::new();
    let mut chars = fmt.chars();
    while let Some(ch) = chars.next() {
        if ch != '%' {
            result.push(ch);
            continue;
        }
        match chars.next() {
            Some('%') => result.push('%'),
            Some('Y') => result.push_str(&format!("{:04}", year)),
            Some('m') => result.push_str(&format!("{:02}", month)),
            Some('d') => result.push_str(&format!("{:02}", day)),
            Some('H') => result.push_str(&format!("{:02}", hour)),
            Some('M') => result.push_str(&format!("{:02}", min)),
            Some('S') => result.push_str(&format!("{:02}", sec)),
            Some('a') => result.push_str(wday_names[wday]),
            Some('b') => result.push_str(month_names[(month - 1) as usize]),
            Some('c') => result.push_str(&format!(
                "{} {} {:2} {:02}:{:02}:{:02} UTC {}",
                wday_names[wday],
                month_names[(month - 1) as usize],
                day,
                hour,
                min,
                sec,
                year
            )),
            Some(other) => {
                result.push('%');
                result.push(other);
            }
            None => result.push('%'),
        }
    }

    let mut w = io::stdout()?;
    wprintln!(w, "{}", result)?;
    Ok(0)
}
