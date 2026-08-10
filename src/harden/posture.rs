/// Security posture score — aggregate all findings into a 0-100 score with letter grade.
use crate::models::{Finding, Severity};

pub struct PostureScore {
    pub score: u32,
    pub grade: char,
    pub total_findings: usize,
    pub by_severity: Vec<(Severity, usize)>,
    pub recommendations: Vec<String>,
}

impl std::fmt::Display for PostureScore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "  Security Posture Score: {}/100 ({})", self.score, self.grade)?;
        writeln!(f, "  ───────────────────────────────────────")?;
        for (sev, count) in &self.by_severity {
            writeln!(f, "  {:<12} {} findings", format!("{:?}", sev), count)?;
        }
        writeln!(f, "  ───────────────────────────────────────")?;
        if !self.recommendations.is_empty() {
            writeln!(f, "  Top recommendations:")?;
            for (i, rec) in self.recommendations.iter().take(5).enumerate() {
                writeln!(f, "  {}. {}", i + 1, rec)?;
            }
        }
        Ok(())
    }
}

pub fn calculate_score(findings: &[Finding]) -> PostureScore {
    let mut counts = std::collections::HashMap::new();
    counts.insert(Severity::Critical, 0);
    counts.insert(Severity::High, 0);
    counts.insert(Severity::Medium, 0);
    counts.insert(Severity::Low, 0);
    counts.insert(Severity::Info, 0);

    for f in findings {
        *counts.entry(f.severity).or_insert(0) += 1;
    }

    let critical = *counts.get(&Severity::Critical).unwrap_or(&0);
    let high = *counts.get(&Severity::High).unwrap_or(&0);
    let medium = *counts.get(&Severity::Medium).unwrap_or(&0);
    let low = *counts.get(&Severity::Low).unwrap_or(&0);
    let info = *counts.get(&Severity::Info).unwrap_or(&0);

    // Weighted penalty
    let penalty = (critical * 25) + (high * 10) + (medium * 5) + (low * 1);
    let score = 100u32.saturating_sub(penalty as u32);

    let grade = match score {
        90..=100 => 'A',
        80..=89 => 'B',
        70..=79 => 'C',
        60..=69 => 'D',
        _ => 'F',
    };

    // Generate recommendations based on top findings
    let mut recommendations = Vec::new();
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity));

    for f in sorted.iter().take(10) {
        if !f.recommendation.is_empty() {
            if !recommendations.contains(&f.recommendation) {
                recommendations.push(f.recommendation.clone());
            }
        }
    }

    let by_severity = vec![
        (Severity::Critical, critical),
        (Severity::High, high),
        (Severity::Medium, medium),
        (Severity::Low, low),
        (Severity::Info, info),
    ];

    PostureScore {
        score,
        grade,
        total_findings: findings.len(),
        by_severity,
        recommendations,
    }
}

/// Compare two scores and show trend.
pub fn compare_scores(old: &PostureScore, new: &PostureScore) -> String {
    let delta = new.score as i32 - old.score as i32;
    let arrow = if delta > 0 { "↑" } else if delta < 0 { "↓" } else { "→" };

    format!(
        "  Score trend: {} {} → {} {} ({}{} points)",
        old.score, old.grade,
        new.score, new.grade,
        arrow,
        delta.abs()
    )
}
