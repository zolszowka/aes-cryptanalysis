from utils.visualizer import PathVisualizer

# TODO: może przenieść do utils?
class DDTHandler:
    """
    Centralna klasa do obsługi Difference Distribution Table (DDT).
    """
    def __init__(self, sbox):
        self.sbox = sbox
        self.size = len(sbox)
        self.ddt = self._generate_ddt()

    def _generate_ddt(self):
        ddt = [[0] * self.size for _ in range(self.size)]
        for d_in in range(self.size):
            for x in range(self.size):
                x_prime = x ^ d_in
                y = self.sbox[x]
                y_prime = self.sbox[x_prime]
                d_out = y ^ y_prime
                ddt[d_in][d_out] += 1
        return ddt

    def get_probability(self, d_in, d_out):
        return self.ddt[d_in][d_out] / self.size

    def get_best_transition(self, d_in):
        """Dla zadanej różnicy wejściowej zwraca (najlepsze_wyjście, prawdopodobieństwo)."""
        if d_in == 0:
            return 0, 1.0

        best_out = -1
        max_count = -1
        
        for d_out in range(self.size):
            count = self.ddt[d_in][d_out]
            if count > max_count:
                max_count = count
                best_out = d_out
        
        return best_out, (max_count / self.size)

    def get_ranked_sbox_transitions(self):
        """
        Zwraca listę wszystkich możliwych przejść (dla d_in > 0),
        posortowaną malejąco według prawdopodobieństwa.
        Returns:
            List[tuple]: (delta_in, delta_out, probability)
        """
        ranking = []
        # Iterujemy przez wszystkie możliwe wejścia (oprócz 0)
        for d_in in range(1, self.size):
            d_out, prob = self.get_best_transition(d_in)
            ranking.append((d_in, d_out, prob))
        
        # Sortowanie: najwyższe prawdopodobieństwo na początku
        ranking.sort(key=lambda x: x[2], reverse=True)
        return ranking

    def visualize(self):
        PathVisualizer.draw_ddt_heatmap(self.ddt)