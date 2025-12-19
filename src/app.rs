mod navigation;

use std::{io, time::Duration};

use crossterm::event::{self, Event, KeyCode};
use ratatui::DefaultTerminal;
use ratatui::widgets::TableState;

use crate::models::{DetailSection, DetailState, DetailTab, NamespaceDetail, NetworkNamespace};
use crate::scanner::{fetch_details, gather_namespaces};
use crate::ui::render_ui;

#[derive(Debug)]
pub enum ViewState {
    List,
    Detail(NamespaceDetail),
}

pub struct App {
    pub namespaces: Vec<NetworkNamespace>,
    pub table_state: TableState,
    pub view_state: ViewState,
    pub exit: bool,
    pub detail_state: DetailState,
    pub is_loading: bool,
}

impl App {
    pub fn new() -> io::Result<App> {
        let namespaces = gather_namespaces()?;
        let mut table_state = TableState::default();
        if !namespaces.is_empty() {
            table_state.select(Some(0));
        }

        Ok(App {
            namespaces,
            table_state,
            view_state: ViewState::List,
            exit: false,
            detail_state: DetailState::default(),
            is_loading: false,
        })
    }

    pub fn run(&mut self, terminal: &mut DefaultTerminal) -> io::Result<()> {
        while !self.exit {
            terminal.draw(|f| render_ui(f, self))?;
            self.handle_events()?;
        }
        Ok(())
    }

    fn handle_events(&mut self) -> io::Result<()> {
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if let ViewState::Detail(_) = self.view_state {
                    if self.detail_state.is_typing_filter {
                        match key.code {
                            KeyCode::Enter => {
                                self.detail_state.is_typing_filter = false;
                            }
                            KeyCode::Char('/') => {
                                self.detail_state.is_typing_filter = false;
                            }
                            KeyCode::Char(c) => {
                                self.detail_state.filter_input.push(c);
                                self.detail_state.processes.select(Some(0));
                            }
                            KeyCode::Backspace => {
                                self.detail_state.filter_input.pop();
                                self.detail_state.processes.select(Some(0));
                            }
                            _ => {}
                        }
                        return Ok(());
                    }
                }

                match key.code {
                    KeyCode::Char('/') => {
                        if let ViewState::Detail(_) = self.view_state {
                            self.detail_state.is_typing_filter = true;
                        }
                    }

                    KeyCode::Char('q') => self.exit = true,
                    KeyCode::Char('r') => self.refresh()?,
                    KeyCode::Down => match self.view_state {
                        ViewState::List => self.next(),
                        ViewState::Detail(_) => self.scroll_detail(false),
                    },
                    KeyCode::Up => match self.view_state {
                        ViewState::List => self.previous(),
                        ViewState::Detail(_) => self.scroll_detail(true),
                    },
                    KeyCode::Enter => self.on_enter(),
                    KeyCode::Esc => self.on_escape(),
                    KeyCode::Tab => self.namespace_detail_focus(),
                    KeyCode::Right => {
                        self.detail_state.active_tab = DetailTab::Internals;
                        self.detail_state.focus = DetailSection::Processes
                    }
                    KeyCode::Left => {
                        self.detail_state.active_tab = DetailTab::Network;
                        self.detail_state.focus = DetailSection::Processes
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn refresh(&mut self) -> io::Result<()> {
        let selected = self.table_state.selected();
        self.namespaces = gather_namespaces()?;

        if let Some(idx) = selected {
            if idx < self.namespaces.len() {
                self.table_state.select(Some(idx));
                if let ViewState::Detail(_) = self.view_state {
                    if let Some(ns) = self.namespaces.get(idx) {
                        let new_details = fetch_details(&ns.ns_path, ns.inode);
                        self.view_state = ViewState::Detail(new_details);
                    }
                }
            } else if !self.namespaces.is_empty() {
                self.table_state.select(Some(0));
            }
        }
        Ok(())
    }
}
