class RiskScorer:
    @staticmethod
    def calculate_trps(cvss: float, epss: float, kev: bool, depth: int, w1=0.4, w2=0.4, w3=0.2, alpha=0.15) -> float:
        """
        Calculates the Transitive Risk Priority Score (TRPS) proposed in the research paper.
        Formula:
        TRPS = [w1 * (CVSS / 10) + w2 * EPSS + w3 * I(KEV)] * [1 / (1 + alpha * Depth)]
        """
        kev_indicator = 1.0 if kev else 0.0

        # Threat magnitude normalization
        threat_magnitude = (w1 * (cvss / 10.0)) + (w2 * epss) + (w3 * kev_indicator)

        # Topological depth penalty factor
        depth_penalty_factor = 1.0 / (1.0 + (alpha * depth))

        trps_score = threat_magnitude * depth_penalty_factor
        return round(trps_score * 100, 2)  # Scaled from 0 to 100