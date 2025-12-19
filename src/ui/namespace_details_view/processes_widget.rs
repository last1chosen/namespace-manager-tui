use ratatui::{
    style::{Color, Style},
    widgets::{Block, Borders, List, ListItem},
};

use crate::models::{DetailSection, ProcessInfo};

pub fn make_processes_widget<'a>(
    processes: &[&'a ProcessInfo],
    focused_state: DetailSection,
) -> List<'a> {
    let items: Vec<ListItem> = processes
        .iter()
        .map(|p| {
            let content = format!("{} ({})", p.name, p.pid);
            ListItem::new(content).style(Style::default().fg(Color::White))
        })
        .collect();

    let title = format!(" Processes ({}) ", processes.len());

    let is_focused = focused_state == DetailSection::Processes;
    let (border_color, highlight_style) = if is_focused {
        (Color::Magenta, Style::default().bg(Color::DarkGray))
    } else {
        (Color::default(), Style::default())
    };

    List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(border_color)),
        )
        .style(Style::default().fg(Color::White))
        .highlight_style(highlight_style)
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[test]
//     fn test_make_processes_widget_count_not_selected() {
//         let processes = vec![
//             ProcessInfo {
//                 pid: 1,
//                 name: "init".into(),
//             },
//             ProcessInfo {
//                 pid: 2,
//                 name: "bash".into(),
//             },
//         ];

//         let _widget = make_processes_widget(&processes, DetailSection::Interfaces);
//     }
// }
