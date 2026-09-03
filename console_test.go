package main

import "testing"

// A trimmed sample of real `armory` output, including the warning lines and
// header rules the parser has to skip.
const armoryIndexSample = `Reading armory index ... done!
[!] https://github.com/sliverarmory/CS-Remote-OPs-BOF - failed to parse pkg manifest: error downloading asset: http 404

 Packages
 Armory    Command Name                    Version   Type        Help
========= =============================== ========= =========== ==========================================
 Default   bof-roast                       v0.0.2    Extension   Beacon Object File repo for roasting AD
 Default   c2tc-askcreds                   v0.0.9    Extension   Collect passwords using CredUIPrompt
 Default   nanodump                        v0.0.5    Extension   Creates a minidump of the LSASS process.
 Default   sa-whoami                       v0.0.28   Extension   Displays current user, group memberships
 Default   rubeus                          v0.0.25   Alias       Kerberos abuse toolkit
 Default   sharp-hound-4                   v0.0.2    Alias       BloodHound collector
`

func TestParseArmoryPackages(t *testing.T) {
	got := parseArmoryPackages(armoryIndexSample)
	want := []string{"bof-roast", "c2tc-askcreds", "nanodump", "sa-whoami", "rubeus", "sharp-hound-4"}
	if len(got) != len(want) {
		t.Fatalf("got %d packages %v, want %d %v", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("package %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// The header row, the ==== rule and the [!] warnings must not be mistaken for
// packages — installing "Command" or "failed" would just produce noise.
func TestParseArmoryPackagesSkipsNonPackageLines(t *testing.T) {
	for _, name := range parseArmoryPackages(armoryIndexSample) {
		switch name {
		case "Command", "Name", "Packages", "Armory", "https://github.com/sliverarmory/CS-Remote-OPs-BOF":
			t.Errorf("parsed %q as a package name", name)
		}
	}
}

func TestParseArmoryPackagesDedupes(t *testing.T) {
	dupes := armoryIndexSample + " Default   sa-whoami                       v0.0.28   Extension   dupe row\n"
	got := parseArmoryPackages(dupes)
	seen := map[string]int{}
	for _, n := range got {
		seen[n]++
	}
	if seen["sa-whoami"] != 1 {
		t.Errorf("sa-whoami appears %d times, want 1", seen["sa-whoami"])
	}
}

func TestParseArmoryPackagesEmptyIndex(t *testing.T) {
	if got := parseArmoryPackages("Reading armory index ... done!\n"); len(got) != 0 {
		t.Errorf("got %v, want no packages", got)
	}
}

// coff-loader is pulled in as a dependency by every BOF extension, so the
// transcript repeats it. Counting raw "Installing" lines reported more installs
// than packages requested ("317 of 174"), which is why this counts distinct names.
func TestParseArmoryInstalledCountsDistinct(t *testing.T) {
	transcript := `[*] Installing extension 'bof-roast' (v0.0.2) ...
[*] Installing extension 'coff-loader' (v1.0.16) ...
[*] Installing extension 'bof-servicemove' (v0.0.1) ...
[*] Installing extension 'coff-loader' (v1.0.16) ...
[*] Installing alias 'rubeus' (v0.0.25) ...
`
	got := parseArmoryInstalled(transcript)
	if len(got) != 4 {
		t.Fatalf("got %d distinct packages %v, want 4", len(got), got)
	}
	want := map[string]bool{"bof-roast": true, "coff-loader": true, "bof-servicemove": true, "rubeus": true}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected package %q", n)
		}
	}
}

func TestIsArmoryInstallAll(t *testing.T) {
	yes := []string{
		"armory install all",
		"  armory install all  ",
		"armory  install   all",
		"ARMORY INSTALL ALL",
		"armory install all -f",
	}
	for _, cmd := range yes {
		if !isArmoryInstallAll(cmd) {
			t.Errorf("isArmoryInstallAll(%q) = false, want true", cmd)
		}
	}
	no := []string{
		"armory install sa-whoami",
		"armory install allocator", // must not match on a prefix
		"armory",
		"armory search all",
		"ls -la all",
		"",
	}
	for _, cmd := range no {
		if isArmoryInstallAll(cmd) {
			t.Errorf("isArmoryInstallAll(%q) = true, want false", cmd)
		}
	}
}

// taskedRE must pull the short task id out of the "Tasked beacon" line the
// one-shot console prints when it queues a beacon task, and must NOT match the
// "Active beacon" line `use` prints (that id is the full UUID, and matching it
// would send us fetching the wrong — or a malformed — task).
func TestTaskedRE(t *testing.T) {
	out := "[*] Active beacon THOUGHTLESS_LITIGATION (29d33767-b1b9-4ce9-9a51-0714ca0adc05)\n" +
		"[*] Tasked beacon THOUGHTLESS_LITIGATION (3a19349b)\n"
	m := taskedRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no match in %q", out)
	}
	if m[1] != "3a19349b" {
		t.Errorf("task id = %q, want %q", m[1], "3a19349b")
	}
}

// A command that queues nothing (client-side output, a parse error) has no
// "Tasked beacon" line, so runBeaconConsole must fall through and return it
// unchanged rather than block waiting for a task that will never exist.
func TestTaskedRENoTask(t *testing.T) {
	for _, out := range []string{
		"[*] Active beacon THOUGHTLESS_LITIGATION (29d33767-b1b9-4ce9-9a51-0714ca0adc05)\n[!] rc line 2 error: parse error: Unterminated backslash-escape",
		"Logon ID: COMMANDO\\Stephen",
	} {
		if m := taskedRE.FindStringSubmatch(out); m != nil {
			t.Errorf("unexpected task-id match %q in %q", m[1], out)
		}
	}
}
