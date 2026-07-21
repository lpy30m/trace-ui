use serde::Serialize;

#[derive(Clone, Debug)]
pub struct EvidenceScoreSignal {
    pub code: String,
    pub label: String,
    pub points: i16,
    pub observed: bool,
    pub evidence: Option<String>,
}

impl EvidenceScoreSignal {
    pub fn new(
        code: impl Into<String>,
        label: impl Into<String>,
        points: i16,
        observed: bool,
        evidence: Option<String>,
    ) -> Self {
        Self {
            code: code.into(),
            label: label.into(),
            points,
            observed,
            evidence,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceScoreFactor {
    pub code: String,
    pub label: String,
    pub points: i16,
    pub observed: bool,
    pub awarded_points: i16,
    pub evidence: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceAssessment {
    pub scope: String,
    pub score: u8,
    pub grade: String,
    pub confidence: String,
    pub verification_gate_met: bool,
    pub factors: Vec<EvidenceScoreFactor>,
    pub limitations: Vec<String>,
}

pub fn score_evidence(
    scope: impl Into<String>,
    verification_gate_met: bool,
    signals: Vec<EvidenceScoreSignal>,
    limitations: Vec<String>,
) -> EvidenceAssessment {
    let factors: Vec<_> = signals
        .into_iter()
        .map(|signal| EvidenceScoreFactor {
            awarded_points: if signal.observed { signal.points } else { 0 },
            code: signal.code,
            label: signal.label,
            points: signal.points,
            observed: signal.observed,
            evidence: signal.evidence,
        })
        .collect();
    let raw_score: i16 = factors.iter().map(|factor| factor.awarded_points).sum();
    let score = raw_score.clamp(0, 100) as u8;
    let (grade, confidence) = if verification_gate_met && score >= 75 {
        ("verified", "high")
    } else if score >= 40 {
        ("related", "medium")
    } else {
        ("uncertain", "low")
    };

    EvidenceAssessment {
        scope: scope.into(),
        score,
        grade: grade.to_string(),
        confidence: confidence.to_string(),
        verification_gate_met,
        factors,
        limitations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verified_requires_both_score_and_gate() {
        let signals = vec![
            EvidenceScoreSignal::new("exact", "Exact recomputation", 65, true, None),
            EvidenceScoreSignal::new("runtime", "Observed at runtime", 20, true, None),
        ];
        let verified = score_evidence("candidate_bytes", true, signals.clone(), Vec::new());
        assert_eq!(verified.score, 85);
        assert_eq!(verified.grade, "verified");

        let related = score_evidence("candidate_bytes", false, signals, Vec::new());
        assert_eq!(related.grade, "related");
    }

    #[test]
    fn penalties_are_explainable_and_clamped() {
        let assessment = score_evidence(
            "investigation",
            false,
            vec![
                EvidenceScoreSignal::new("search", "Search evidence", 20, true, None),
                EvidenceScoreSignal::new("truncated", "Result truncated", -30, true, None),
            ],
            vec!["Dynamic trace only".to_string()],
        );
        assert_eq!(assessment.score, 0);
        assert_eq!(assessment.grade, "uncertain");
        assert_eq!(assessment.factors[1].awarded_points, -30);
    }
}
