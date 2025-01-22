use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem},
    Terminal,
};
use std::{
    collections::VecDeque,
    sync::mpsc,
    time::{Duration, Instant},
};

pub struct LogEntry {
    pub timestamp: String,
    pub level: String,
    pub message: String,
}

pub struct App {
    logs: VecDeque<LogEntry>,
    should_quit: bool,
}

impl App {
    pub fn new() -> App {
        App {
            logs: VecDeque::with_capacity(100),
            should_quit: false,
        }
    }

    pub fn add_log(&mut self, entry: LogEntry) {
        if self.logs.len() >= 100 {
            self.logs.pop_front();
        }
        self.logs.push_back(entry);
    }
}

pub fn run_app(rx: mpsc::Receiver<LogEntry>) -> Result<(), Box<dyn std::error::Error>> {
    // Terminal initialization
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let mut last_tick = Instant::now();
    let tick_rate = Duration::from_millis(250);

    loop {
        terminal.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .margin(1)
                .constraints(
                    [
                        Constraint::Min(0), // Logs
                    ]
                    .as_ref(),
                )
                .split(f.area());

            // Logs
            let logs: Vec<ListItem> = app
                .logs
                .iter()
                .map(|log| {
                    let color = match log.level.as_str() {
                        "ERROR" => Color::Red,
                        "WARN" => Color::Yellow,
                        "INFO" => Color::Blue,
                        "DEBUG" => Color::Green,
                        _ => Color::White,
                    };

                    ListItem::new(Line::from(vec![
                        Span::styled(&log.timestamp, Style::default().fg(Color::DarkGray)),
                        Span::raw(" "),
                        Span::styled(
                            format!("[{}]", log.level),
                            Style::default().fg(color).add_modifier(Modifier::BOLD),
                        ),
                        Span::raw(" "),
                        Span::raw(&log.message),
                    ]))
                })
                .collect();

            let logs =
                List::new(logs).block(Block::default().borders(Borders::ALL).title("Server Logs"));
            f.render_widget(logs, chunks[0]);
        })?;

        let timeout = tick_rate
            .checked_sub(last_tick.elapsed())
            .unwrap_or_else(|| Duration::from_secs(0));

        if crossterm::event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    app.should_quit = true;
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            // Check for new log entries
            if let Ok(log_entry) = rx.try_recv() {
                app.add_log(log_entry);
            }
            last_tick = Instant::now();
        }

        if app.should_quit {
            break;
        }
    }

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}
