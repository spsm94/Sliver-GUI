package main

import (
	"testing"

	"github.com/bishopfox/sliver/protobuf/clientpb"
)

// buildShellcodeConfig has to reproduce parseShellcodeFlags' gating rules, and
// getting them wrong is silent: the server accepts an out-of-range Donut value
// and the build fails much later, or Donut fields ride along on a Linux target
// that ignores them. These pin the rules down.
func TestBuildShellcodeConfig(t *testing.T) {
	tests := []struct {
		name   string
		opts   GenerateOptions
		format clientpb.OutputFormat
		want   *clientpb.ShellcodeConfig
	}{{
		name:   "nil unless the output format is shellcode",
		opts:   GenerateOptions{OS: "windows", ShellcodeCompress: true, ShellcodeEntropy: 3},
		format: clientpb.OutputFormat_EXECUTABLE,
		want:   nil,
	}, {
		// Donut is Windows-only; beignet/malasada implement compression alone.
		name:   "linux carries compression only",
		opts:   GenerateOptions{OS: "linux", ShellcodeCompress: true, ShellcodeEntropy: 3, ShellcodeThread: true},
		format: clientpb.OutputFormat_SHELLCODE,
		want:   &clientpb.ShellcodeConfig{Compress: 2},
	}, {
		name:   "darwin carries compression only",
		opts:   GenerateOptions{OS: "darwin", ShellcodeCompress: false, ShellcodeOEP: 4096},
		format: clientpb.OutputFormat_SHELLCODE,
		want:   &clientpb.ShellcodeConfig{Compress: 1},
	}, {
		// A client that omits the shellcode fields sends zeros, which Donut
		// rejects — they must land on Donut's own defaults, not on 0.
		name:   "zero values fall back to Donut defaults",
		opts:   GenerateOptions{OS: "windows"},
		format: clientpb.OutputFormat_SHELLCODE,
		want:   &clientpb.ShellcodeConfig{Entropy: 1, Compress: 1, ExitOpt: 1, Bypass: 3, Headers: 1},
	}, {
		name: "out-of-range values fall back to Donut defaults",
		opts: GenerateOptions{OS: "windows", ShellcodeEntropy: 9, ShellcodeExitOpt: 4,
			ShellcodeBypass: 0, ShellcodeHeaders: 3},
		format: clientpb.OutputFormat_SHELLCODE,
		want:   &clientpb.ShellcodeConfig{Entropy: 1, Compress: 1, ExitOpt: 1, Bypass: 3, Headers: 1},
	}, {
		name: "in-range values pass through",
		opts: GenerateOptions{OS: "windows", ShellcodeCompress: true, ShellcodeEntropy: 2,
			ShellcodeExitOpt: 3, ShellcodeBypass: 2, ShellcodeHeaders: 2,
			ShellcodeThread: true, ShellcodeUnicode: true, ShellcodeOEP: 4096},
		format: clientpb.OutputFormat_SHELLCODE,
		want: &clientpb.ShellcodeConfig{Entropy: 2, Compress: 2, ExitOpt: 3, Bypass: 2,
			Headers: 2, Thread: true, Unicode: true, OEP: 4096},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := buildShellcodeConfig(tc.opts, tc.format)
			if tc.want == nil {
				if got != nil {
					t.Fatalf("got %+v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("got nil, want %+v", tc.want)
			}
			if got.Entropy != tc.want.Entropy || got.Compress != tc.want.Compress ||
				got.ExitOpt != tc.want.ExitOpt || got.Bypass != tc.want.Bypass ||
				got.Headers != tc.want.Headers || got.Thread != tc.want.Thread ||
				got.Unicode != tc.want.Unicode || got.OEP != tc.want.OEP {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

// The GUI sends whatever the arch dropdown holds; the encoder map is keyed by
// Go's arch names, so the aliases have to fold before the lookup.
func TestNormalizeShellcodeArch(t *testing.T) {
	for in, want := range map[string]string{
		"amd64": "amd64", "x64": "amd64", "X86_64": "amd64",
		"386": "386", "x86": "386", "i386": "386",
		"arm64": "arm64", "aarch64": "arm64", " ARM64 ": "arm64",
		"mips": "mips",
	} {
		if got := normalizeShellcodeArch(in); got != want {
			t.Errorf("normalizeShellcodeArch(%q) = %q, want %q", in, got, want)
		}
	}
}

// buildImplantConfig gained a pile of new fields; the contract that matters is
// that a caller which sets none of them (the Generate modal) is unaffected.
func TestBuildImplantConfigDefaultsUnchanged(t *testing.T) {
	cfg := buildImplantConfig(GenerateOptions{
		OS: "windows", Arch: "amd64", Format: "exe",
		C2Type: "mtls", C2Host: "1.2.3.4", C2Port: 8888,
	}, clientpb.ShellcodeEncoder_NONE)

	if cfg.Debug || cfg.Evasion || cfg.ObfuscateSymbols || cfg.RunAtLoad ||
		cfg.NetGoEnabled || cfg.LimitDomainJoined || cfg.SGNEnabled {
		t.Errorf("an option defaulted to on: %+v", cfg)
	}
	if cfg.LimitHostname != "" || cfg.LimitUsername != "" || cfg.LimitDatetime != "" ||
		cfg.LimitFileExists != "" || cfg.LimitLocale != "" {
		t.Errorf("a limit defaulted to non-empty: %+v", cfg)
	}
	if cfg.ShellcodeConfig != nil {
		t.Errorf("ShellcodeConfig set on a non-shellcode build: %+v", cfg.ShellcodeConfig)
	}
	if cfg.ShellcodeEncoder != clientpb.ShellcodeEncoder_NONE {
		t.Errorf("ShellcodeEncoder = %v, want NONE", cfg.ShellcodeEncoder)
	}
}

// SGNEnabled is the legacy mirror the server still consults; it must track the
// encoder choice rather than being left false.
func TestBuildImplantConfigSGNMirrorsEncoder(t *testing.T) {
	opts := GenerateOptions{OS: "windows", Arch: "amd64", Format: "shellcode",
		C2Type: "mtls", C2Host: "1.2.3.4", C2Port: 8888}

	if cfg := buildImplantConfig(opts, clientpb.ShellcodeEncoder_SHIKATA_GA_NAI); !cfg.SGNEnabled {
		t.Error("SGNEnabled = false for the shikata_ga_nai encoder, want true")
	}
	if cfg := buildImplantConfig(opts, clientpb.ShellcodeEncoder_XOR); cfg.SGNEnabled {
		t.Error("SGNEnabled = true for the xor encoder, want false")
	}
}
