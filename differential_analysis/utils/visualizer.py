class PathVisualizer:
    """
    Klasa do generowania ładnych wizualizacji w terminalu dla kryptoanalizy.
    Używa kodów ANSI do kolorowania.
    """
    
    # Kolory ANSI
    C_RESET  = "\033[0m"
    C_BOLD   = "\033[1m"
    C_DIM    = "\033[2m"
    C_RED    = "\033[91m"
    C_GREEN  = "\033[92m"
    C_YELLOW = "\033[93m"
    C_BLUE   = "\033[94m"
    C_CYAN   = "\033[96m"
    
    @staticmethod
    def print_header(text):
        print(f"\n{PathVisualizer.C_BOLD}{PathVisualizer.C_BLUE}" + "="*60)
        print(f" {text}")
        print("="*60 + f"{PathVisualizer.C_RESET}")

    @staticmethod
    def draw_ddt_heatmap(ddt):
        """Rysuje tabelę DDT z kolorowaniem prawdopodobieństw."""
        PathVisualizer.print_header("DIFFERENCE DISTRIBUTION TABLE (DDT) HEATMAP")
        
        # Nagłówek kolumn
        print("   |", end="")
        for i in range(16):
            print(f" {i:X} ", end="")
        print(f"\n{PathVisualizer.C_DIM}---+-" + "---"*16 + f"{PathVisualizer.C_RESET}")

        for d_in, row in enumerate(ddt):
            # Nagłówek wiersza
            print(f" {d_in:X} |", end="")
            
            for count in row:
                val_str = f"{count:>2}"
                
                # Logika kolorowania
                if count == 0:
                    # Kropka dla zera (żeby nie zaciemniać obrazu)
                    print(f"{PathVisualizer.C_DIM}  .{PathVisualizer.C_RESET}", end="")
                elif count == 16:
                    # Przypadek trywialny (0->0)
                    print(f"{PathVisualizer.C_DIM}{val_str} {PathVisualizer.C_RESET}", end="")
                elif count >= 8:
                    # Bardzo wysokie prawdopodobieństwo (Gorące!)
                    print(f"{PathVisualizer.C_BOLD}{PathVisualizer.C_GREEN}{val_str} {PathVisualizer.C_RESET}", end="")
                elif count >= 4:
                    # Średnie
                    print(f"{PathVisualizer.C_YELLOW}{val_str} {PathVisualizer.C_RESET}", end="")
                else:
                    # Niskie
                    print(f"{val_str} ", end="")
            print(f"{PathVisualizer.C_DIM}|{PathVisualizer.C_RESET}") # Koniec wiersza

    @staticmethod
    def _draw_block_bits(value, label, color=C_CYAN):
        """Pomocnicza funkcja rysująca blok 16-bitowy jako pudełka."""
        # Rozbicie na nibble
        n0 = (value >> 12) & 0xF
        n1 = (value >> 8) & 0xF
        n2 = (value >> 4) & 0xF
        n3 = value & 0xF
        
        hex_str = f"0x{value:04X}"
        bin_str = f"{value:016b}"
        formatted_bin = f"{bin_str[0:4]} {bin_str[4:8]} {bin_str[8:12]} {bin_str[12:16]}"
        
        print(f"{PathVisualizer.C_BOLD}{label:<15}{PathVisualizer.C_RESET} ", end="")
        print(f"{color}[ {n0:X} ][ {n1:X} ][ {n2:X} ][ {n3:X} ]{PathVisualizer.C_RESET}", end="")
        print(f"  Hex: {PathVisualizer.C_BOLD}{hex_str}{PathVisualizer.C_RESET}")
        print(f"{' '*16}{PathVisualizer.C_DIM}  Bin: {formatted_bin}{PathVisualizer.C_RESET}\n")

    @staticmethod
    def visualize_path_step_by_step(step_data):
        """
        Wizualizuje przepływ różnicy przez rundę.
        step_data = {
            'input': int,
            'sbox_out': int,
            'shift_out': int,
            'mix_out': int,
            'prob': float
        }
        """
        PathVisualizer.print_header("SYMULACJA ŚCIEŻKI (RUNDA 1)")
        
        # 1. Wejście
        PathVisualizer._draw_block_bits(step_data['input'], "INPUT (Delta)", PathVisualizer.C_BLUE)
        
        print(f"{PathVisualizer.C_YELLOW}      ||")
        print(f"      ||  S-BOX LAYER (Prob: {step_data['prob']:.1f}%)")
        print(f"      \\/{PathVisualizer.C_RESET}")
        
        # 2. Po S-boxach
        PathVisualizer._draw_block_bits(step_data['sbox_out'], "AFTER S-BOX", PathVisualizer.C_GREEN)

        print(f"{PathVisualizer.C_YELLOW}      ||")
        print(f"      ||  SHIFT ROWS (Permutacja)")
        print(f"      \\/{PathVisualizer.C_RESET}")

        # 3. Po ShiftRows
        PathVisualizer._draw_block_bits(step_data['shift_out'], "AFTER SHIFT", PathVisualizer.C_CYAN)

        print(f"{PathVisualizer.C_YELLOW}      ||")
        print(f"      ||  MIX COLUMNS (Dyfuzja)")
        print(f"      \\/{PathVisualizer.C_RESET}")

        # 4. Wyjście (Target)
        PathVisualizer._draw_block_bits(step_data['mix_out'], "ROUND 2 INPUT", PathVisualizer.C_RED)
        
        print(f"\n{PathVisualizer.C_BOLD}WNIOSEK:{PathVisualizer.C_RESET}")
        print(f"Szukamy różnicy {PathVisualizer.C_RED}0x{step_data['mix_out']:04X}{PathVisualizer.C_RESET} "
              f"przed S-boxami rundy 2.")