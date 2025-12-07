from differential_analysis.utils.visualizer import PathVisualizer

class DDTHandler:
    """
    Centralna klasa do obsługi Difference Distribution Table (DDT).
    Oblicza tabelę raz i udostępnia metody analityczne.
    """
    def __init__(self, sbox):
        self.sbox = sbox
        self.size = len(sbox)
        self.ddt = self._generate_ddt()

    def _generate_ddt(self):
        """Wewnętrzna metoda generująca tabelę NxN."""
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
        """Zwraca prawdopodobieństwo przejścia (0.0 - 1.0)."""
        return self.ddt[d_in][d_out] / self.size

    def get_best_transition(self, d_in):
        """
        Dla zadanej różnicy wejściowej zwraca (najlepsza_różnica_wyjściowa, prawdopodobieństwo).
        """
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

    def find_global_best_transition(self):
        """Znajduje najlepsze przejście w całym DDT (pomijając 0->0)."""
        best_in = -1
        best_out = -1
        max_prob = -1
        
        for d_in in range(1, self.size):
            out, prob = self.get_best_transition(d_in)
            if prob > max_prob:
                max_prob = prob
                best_in = d_in
                best_out = out
                
        return best_in, best_out, max_prob

    def visualize(self):
        """Wyświetla heatmapę DDT."""
        PathVisualizer.draw_ddt_heatmap(self.ddt)