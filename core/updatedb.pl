#!/usr/bin/perl
# core/updatedb.pl - Download and merge vulnerability data from public sources

# Check required modules
my $can_https_db = 1;
eval { require LWP::Protocol::https; };
if ($@) { $can_https_db = 0; }

if (!$can_https_db) {
    print color("red");
    print "[!] Database update requires HTTPS, but LWP::Protocol::https is not available!\n";
    print "[!] Try: cpan LWP::Protocol::https\n\n";
    print color("reset");
    return;
}

my $has_json_pp = 1;
eval { require JSON::PP; JSON::PP->import(); };
if ($@) { $has_json_pp = 0; }

if (!$has_json_pp) {
    print color("red");
    print "[!] Database update requires JSON::PP (core since Perl 5.14)!\n";
    print "[!] Try: cpan JSON::PP\n\n";
    print color("reset");
    return;
}

use File::Path qw(make_path);
use File::Copy;
use POSIX qw(strftime);

# Configuration
my $dbpath       = "$mepath/exploit/db";
my $comvul_file  = "$dbpath/comvul.txt";
my $corevul_file = "$dbpath/corevul.txt";
my $complist_file = "$dbpath/componentslist.txt";

my $src_joomlavs_components = 'https://raw.githubusercontent.com/rastating/joomlavs/master/data/components.json';
my $src_joomlavs_joomla     = 'https://raw.githubusercontent.com/rastating/joomlavs/master/data/joomla.json';
my $src_exploitdb_csv       = 'https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv';

# Create HTTP client
my $db_browser = LWP::UserAgent->new(ssl_opts => { verify_hostname => 0 });
$db_browser->timeout(120);
$db_browser->protocols_allowed(['http', 'https']);
$db_browser->agent('Mozilla/5.0 (compatible; JoomScan DB Updater)');

# Print banner
print "\n";
print color("cyan");
print "[*] OWASP JoomScan Vulnerability Database Updater\n";
print color("reset");
print "[*] Updating vulnerability databases from public sources...\n\n";

# Data stores (keyed by dedup key)
my %comvul_entries;
my %corevul_entries;
my %component_names;

# Step 1: Load existing data
db_load_existing();

my $sources_ok = 0;

# Step 2: Download and merge each source
print color("cyan");
print "[*] Downloading source 1/3: joomlavs components.json\n";
print color("reset");
eval { db_merge_joomlavs_components(); };
if ($@) {
    chomp(my $err = $@);
    print color("red");
    print "[!] Failed: $err\n";
    print color("reset");
}

print color("cyan");
print "[*] Downloading source 2/3: joomlavs joomla.json\n";
print color("reset");
eval { db_merge_joomlavs_joomla(); };
if ($@) {
    chomp(my $err = $@);
    print color("red");
    print "[!] Failed: $err\n";
    print color("reset");
}

print color("cyan");
print "[*] Downloading source 3/3: Exploit-DB CSV\n";
print color("reset");
eval { db_merge_exploitdb_csv(); };
if ($@) {
    chomp(my $err = $@);
    print color("red");
    print "[!] Failed: $err\n";
    print color("reset");
}

if ($sources_ok == 0) {
    print color("red");
    print "\n[!] All downloads failed. Database not updated.\n\n";
    print color("reset");
    return;
}

# Step 3: Backup existing files
db_backup_files();

# Step 4: Write merged data
db_write_comvul();
db_write_corevul();
db_write_componentslist();

# Print summary
print color("green");
print "\n[+] Database update complete!\n";
print color("reset");
print "[*] Component vulnerabilities: " . scalar(keys %comvul_entries) . " entries\n";
print "[*] Core vulnerabilities: " . scalar(keys %corevul_entries) . " entries\n";
print "[*] Components list: " . scalar(keys %component_names) . " entries\n\n";

###############################################################################
# Subroutines
###############################################################################

sub db_fetch_url {
    my ($url) = @_;
    print "    Fetching: $url\n";
    my $response = $db_browser->get($url);
    if (!$response->is_success) {
        die "HTTP " . $response->status_line . " for $url\n";
    }
    return $response->decoded_content;
}

# Dedup key for comvul entries: component|edb_id|cve (with title fallback)
sub db_comvul_key {
    my ($component, $edb_id, $cve, $title) = @_;
    $component = lc($component // '-');
    $edb_id = '-' unless defined $edb_id && $edb_id =~ /\d/;
    $cve    = '-' unless defined $cve    && $cve    =~ /\d/;
    my $key = "$component|$edb_id|$cve";
    # Include title when both identifiers are missing to avoid false dedup
    if ($edb_id eq '-' && $cve eq '-') {
        $key .= '|' . lc($title // '');
    }
    return $key;
}

# Dedup key for corevul entries: lowercased title
sub db_corevul_key {
    my ($title) = @_;
    $title //= '';
    $title =~ s/^\s+|\s+$//g;
    return lc($title);
}

# Strip "CVE-" prefix, returning just the numeric part (e.g. "2015-1234")
sub db_strip_cve_prefix {
    my ($cve) = @_;
    return undef unless defined $cve && $cve =~ /\d/;
    $cve =~ s/^\s+|\s+$//g;
    $cve =~ s/^CVE-//i;
    return $cve;
}

# Try multiple possible JSON field names, return first defined non-empty value
sub db_get_json_field {
    my ($hash, @keys) = @_;
    for my $key (@keys) {
        if (exists $hash->{$key} && defined $hash->{$key} && $hash->{$key} ne '') {
            return $hash->{$key};
        }
    }
    return undef;
}

# Format a comvul.txt line: [title][component][date][CVE][-][EDB-ID][fixed_in][introduced_in]
sub db_format_comvul_line {
    my ($title, $component, $date, $cve, $edb_id, $fixed_in, $introduced_in) = @_;
    $title         //= '-';
    $component     //= '-';
    $date          //= '-';
    $cve           //= '-';
    $edb_id        //= '-';
    $fixed_in      //= '-';
    $introduced_in //= '-';
    return "[$title][$component][$date][$cve][-][$edb_id][$fixed_in][$introduced_in]";
}

# Format a corevul.txt line: versions|title\nCVE : CVE-XXXX\nEDB : url
sub db_format_corevul_line {
    my ($versions_str, $title, $cve, $edb_id) = @_;
    my $desc = $title;
    if (defined $cve && $cve =~ /\S/ && $cve ne '-') {
        $desc .= "\\nCVE : $cve";
    }
    if (defined $edb_id && $edb_id =~ /\d/) {
        $desc .= "\\nEDB : https://www.exploit-db.com/exploits/$edb_id/";
    }
    return "$versions_str|$desc";
}

###############################################################################
# Load existing database files into memory
###############################################################################
sub db_load_existing {
    # Load comvul.txt
    if (open(my $fh, '<', $comvul_file)) {
        while (my $line = <$fh>) {
            chomp $line;
            next unless $line =~ /\S/;
            my @fields;
            while ($line =~ /\[(.*?)\]/g) {
                push @fields, $1;
            }
            if (scalar @fields >= 6) {
                my $key = db_comvul_key($fields[1], $fields[5], $fields[3], $fields[0]);
                $comvul_entries{$key} = $line;
            }
        }
        close($fh);
    }
    print "[*] Loaded " . scalar(keys %comvul_entries) . " existing component vulnerabilities\n";

    # Load corevul.txt
    if (open(my $fh, '<', $corevul_file)) {
        while (my $line = <$fh>) {
            chomp $line;
            next unless $line =~ /\S/;
            my $idx = index($line, '|');
            if ($idx >= 0) {
                my $desc = substr($line, $idx + 1);
                # Title is everything before the first literal \n
                my $title = $desc;
                $title =~ s/\\n.*//;
                my $key = db_corevul_key($title);
                $corevul_entries{$key} = $line;
            }
        }
        close($fh);
    }
    print "[*] Loaded " . scalar(keys %corevul_entries) . " existing core vulnerabilities\n";

    # Load componentslist.txt
    if (open(my $fh, '<', $complist_file)) {
        while (my $line = <$fh>) {
            chomp $line;
            next unless $line =~ /\S/;
            $component_names{$line} = 1;
        }
        close($fh);
    }
    print "[*] Loaded " . scalar(keys %component_names) . " existing components\n\n";
}

###############################################################################
# Source 1: joomlavs components.json
###############################################################################
sub db_merge_joomlavs_components {
    my $content = db_fetch_url($src_joomlavs_components);
    my $data = JSON::PP::decode_json($content);

    my $added   = 0;
    my $skipped = 0;

    if (ref $data eq 'HASH') {
        # Structure: { "com_name": { "vulns": [ {...}, ... ] }, ... }
        for my $comp_name (sort keys %{$data}) {
            my $comp_data = $data->{$comp_name};
            my $vulns;
            if (ref $comp_data eq 'HASH') {
                $vulns = $comp_data->{vulns} // $comp_data->{vulnerabilities} // [];
            } else {
                $vulns = [];
            }
            $vulns = [$vulns] if ref $vulns ne 'ARRAY';

            my $short_name = $comp_name;
            $short_name =~ s/^com_//i;

            my $full_name = $comp_name =~ /^com_/i ? $comp_name : "com_$comp_name";
            $component_names{$full_name} = 1;

            for my $vuln (@{$vulns}) {
                next unless ref $vuln eq 'HASH';

                my $title    = db_get_json_field($vuln, 'title', 'name', 'description') // '-';
                my $edb_id   = db_get_json_field($vuln, 'edb_id', 'edbid', 'exploitdb_id', 'id');
                my $cve_raw  = db_get_json_field($vuln, 'cve', 'cve_id', 'cveid');
                my $fixed_in = db_get_json_field($vuln, 'fixed_in', 'fixed', 'patched_in');
                my $intro    = db_get_json_field($vuln, 'introduced_in', 'introduced');
                my $date     = db_get_json_field($vuln, 'date', 'published_date', 'disclosure_date');

                # CVE might be an array
                if (ref $cve_raw eq 'ARRAY') {
                    $cve_raw = join(',', grep { defined $_ && $_ =~ /\S/ } @{$cve_raw});
                }

                my $cve = db_strip_cve_prefix($cve_raw);

                my $key = db_comvul_key($short_name, $edb_id, $cve, $title);
                if (!exists $comvul_entries{$key}) {
                    $comvul_entries{$key} = db_format_comvul_line(
                        $title, $short_name, $date // '-',
                        $cve // '-', $edb_id // '-',
                        $fixed_in // '-', $intro // '-'
                    );
                    $added++;
                } else {
                    $skipped++;
                }
            }
        }
    } elsif (ref $data eq 'ARRAY') {
        # Structure: [ { "name": "com_x", "vulns": [...] }, ... ]
        for my $item (@{$data}) {
            next unless ref $item eq 'HASH';

            my $comp_name = db_get_json_field($item, 'name', 'component', 'slug');
            next unless defined $comp_name;

            my $vulns = $item->{vulns} // $item->{vulnerabilities} // [$item];
            $vulns = [$vulns] if ref $vulns ne 'ARRAY';

            my $short_name = $comp_name;
            $short_name =~ s/^com_//i;

            my $full_name = $comp_name =~ /^com_/i ? $comp_name : "com_$comp_name";
            $component_names{$full_name} = 1;

            for my $vuln (@{$vulns}) {
                next unless ref $vuln eq 'HASH';

                my $title    = db_get_json_field($vuln, 'title', 'name', 'description') // '-';
                my $edb_id   = db_get_json_field($vuln, 'edb_id', 'edbid', 'exploitdb_id', 'id');
                my $cve_raw  = db_get_json_field($vuln, 'cve', 'cve_id', 'cveid');
                my $fixed_in = db_get_json_field($vuln, 'fixed_in', 'fixed', 'patched_in');
                my $intro    = db_get_json_field($vuln, 'introduced_in', 'introduced');
                my $date     = db_get_json_field($vuln, 'date', 'published_date', 'disclosure_date');

                if (ref $cve_raw eq 'ARRAY') {
                    $cve_raw = join(',', grep { defined $_ && $_ =~ /\S/ } @{$cve_raw});
                }

                my $cve = db_strip_cve_prefix($cve_raw);

                my $key = db_comvul_key($short_name, $edb_id, $cve, $title);
                if (!exists $comvul_entries{$key}) {
                    $comvul_entries{$key} = db_format_comvul_line(
                        $title, $short_name, $date // '-',
                        $cve // '-', $edb_id // '-',
                        $fixed_in // '-', $intro // '-'
                    );
                    $added++;
                } else {
                    $skipped++;
                }
            }
        }
    } else {
        die "Unexpected JSON structure in components.json\n";
    }

    print "    Added $added new component vulnerabilities ($skipped already existed)\n";
    $sources_ok++;
}

###############################################################################
# Source 2: joomlavs joomla.json (core vulnerabilities)
###############################################################################
sub db_merge_joomlavs_joomla {
    my $content = db_fetch_url($src_joomlavs_joomla);
    my $data = JSON::PP::decode_json($content);

    my $added   = 0;
    my $skipped = 0;

    my @vulns;
    if (ref $data eq 'ARRAY') {
        @vulns = @{$data};
    } elsif (ref $data eq 'HASH') {
        if (exists $data->{vulns}) {
            @vulns = @{$data->{vulns}};
        } else {
            for my $k (keys %{$data}) {
                my $val = $data->{$k};
                if (ref $val eq 'ARRAY') {
                    push @vulns, @{$val};
                } elsif (ref $val eq 'HASH') {
                    push @vulns, $val;
                }
            }
        }
    }

    for my $vuln (@vulns) {
        next unless ref $vuln eq 'HASH';

        my $title    = db_get_json_field($vuln, 'title', 'name', 'description');
        next unless defined $title && $title =~ /\S/;

        my $edb_id   = db_get_json_field($vuln, 'edb_id', 'edbid', 'exploitdb_id');
        my $cve_raw  = db_get_json_field($vuln, 'cve', 'cve_id', 'cveid');
        my $fixed_in = db_get_json_field($vuln, 'fixed_in', 'fixed', 'patched_in');
        my $versions = db_get_json_field($vuln, 'versions', 'affected_versions');

        # Format CVE with prefix for corevul
        my $cve_formatted;
        if (ref $cve_raw eq 'ARRAY') {
            my @parts = grep { defined $_ && $_ =~ /\S/ } @{$cve_raw};
            if (@parts) {
                $cve_formatted = join(' , ', map { "CVE-" . db_strip_cve_prefix($_) } @parts);
            }
        } elsif (defined $cve_raw && $cve_raw =~ /\d/) {
            $cve_formatted = "CVE-" . db_strip_cve_prefix($cve_raw);
        }

        # Build versions string
        my $versions_str = '';
        if (ref $versions eq 'ARRAY' && @{$versions}) {
            $versions_str = join(',', @{$versions});
        } elsif (defined $versions && !ref $versions) {
            $versions_str = $versions;
        }

        # Fallback: try fixed_in as the affected version
        if ($versions_str eq '' && defined $fixed_in && $fixed_in =~ /\d/) {
            $versions_str = $fixed_in;
        }

        # Fallback: extract version from title
        if ($versions_str eq '') {
            if ($title =~ /(\d+\.\d+(?:\.\d+)*)/) {
                $versions_str = $1;
            } else {
                next; # Cannot determine affected version
            }
        }

        my $key = db_corevul_key($title);
        if (!exists $corevul_entries{$key}) {
            $corevul_entries{$key} = db_format_corevul_line(
                $versions_str, $title, $cve_formatted, $edb_id
            );
            $added++;
        } else {
            $skipped++;
        }
    }

    print "    Added $added new core vulnerabilities ($skipped already existed)\n";
    $sources_ok++;
}

###############################################################################
# Source 3: Exploit-DB CSV
###############################################################################
sub db_merge_exploitdb_csv {
    my $content = db_fetch_url($src_exploitdb_csv);
    $content =~ s/\r\n/\n/g;  # Normalize line endings
    my @lines = split(/\n/, $content);
    die "Empty CSV file\n" unless @lines;

    # Parse header to find column indices
    my $header = shift @lines;
    my @hdr_fields = db_parse_csv_line($header);
    my %col;
    for my $i (0 .. $#hdr_fields) {
        $col{lc($hdr_fields[$i])} = $i;
    }

    my $id_col   = $col{id}          // die "No 'id' column in Exploit-DB CSV\n";
    my $desc_col = $col{description}  // die "No 'description' column in Exploit-DB CSV\n";
    my $date_col = $col{date_published} // $col{date};
    my $cve_col  = $col{codes} // $col{cve} // $col{cve_id};

    my $comp_added = 0;
    my $core_added = 0;
    my $skipped    = 0;

    for my $csvline (@lines) {
        next unless $csvline =~ /\S/;
        my @fields = db_parse_csv_line($csvline);

        my $edb_id = $fields[$id_col];
        next unless defined $edb_id && $edb_id =~ /\d/;

        my $desc = $fields[$desc_col] // '';

        # Filter: only Joomla-related entries
        next unless $desc =~ /joomla/i;

        my $date = '-';
        if (defined $date_col && defined $fields[$date_col]) {
            $date = $fields[$date_col];
            $date =~ s/^\s+|\s+$//g;
        }

        # Try to get CVE from dedicated column or from description text
        my $cve_raw = '';
        if (defined $cve_col && defined $fields[$cve_col] && $fields[$cve_col] =~ /\d{4}-\d+/) {
            $cve_raw = $fields[$cve_col];
        }
        if ($cve_raw !~ /\d{4}-\d+/) {
            my @cves_in_desc;
            while ($desc =~ /CVE-(\d{4}-\d+)/gi) {
                push @cves_in_desc, $1;
            }
            $cve_raw = join(',', @cves_in_desc) if @cves_in_desc;
        }

        my $cve = db_strip_cve_prefix($cve_raw);

        # Determine if this is a component vuln or core vuln
        if ($desc =~ /com_(\w+)/i) {
            my $comp_name = $1;

            $component_names{"com_$comp_name"} = 1;

            my $key = db_comvul_key($comp_name, $edb_id, $cve, $desc);
            if (!exists $comvul_entries{$key}) {
                $comvul_entries{$key} = db_format_comvul_line(
                    $desc, $comp_name, $date,
                    $cve // '-', $edb_id, '-', '-'
                );
                $comp_added++;
            } else {
                $skipped++;
            }
        } else {
            # Core Joomla vulnerability - extract version from description
            my $version = '-';
            if ($desc =~ /(\d+\.\d+(?:\.\d+)*)/) {
                $version = $1;
            } else {
                next; # Skip entries with no version info
            }

            my $key = db_corevul_key($desc);
            if (!exists $corevul_entries{$key}) {
                # Format CVE with prefix for corevul
                my $cve_formatted;
                if (defined $cve && $cve =~ /\d/) {
                    my @parts = split(/,/, $cve);
                    $cve_formatted = join(' , ', map { "CVE-$_" } @parts);
                }

                $corevul_entries{$key} = db_format_corevul_line(
                    $version, $desc, $cve_formatted, $edb_id
                );
                $core_added++;
            } else {
                $skipped++;
            }
        }
    }

    print "    Added $comp_added component + $core_added core vulnerabilities ($skipped already existed)\n";
    $sources_ok++;
}

###############################################################################
# CSV parser (handles quoted fields with embedded commas)
###############################################################################
sub db_parse_csv_line {
    my ($line) = @_;
    my @fields;
    my $pos = 0;
    my $len = length($line);

    while ($pos <= $len) {
        my $field = '';
        if ($pos < $len && substr($line, $pos, 1) eq '"') {
            # Quoted field
            $pos++; # skip opening quote
            while ($pos < $len) {
                my $ch = substr($line, $pos, 1);
                if ($ch eq '"') {
                    if ($pos + 1 < $len && substr($line, $pos + 1, 1) eq '"') {
                        $field .= '"';
                        $pos += 2;
                    } else {
                        $pos++; # skip closing quote
                        last;
                    }
                } else {
                    $field .= $ch;
                    $pos++;
                }
            }
            # Skip comma after quoted field
            if ($pos < $len && substr($line, $pos, 1) eq ',') {
                $pos++;
            } else {
                $pos = $len + 1;
            }
        } else {
            # Unquoted field
            my $end = index($line, ',', $pos);
            if ($end == -1) {
                $field = substr($line, $pos);
                $pos = $len + 1;
            } else {
                $field = substr($line, $pos, $end - $pos);
                $pos = $end + 1;
            }
        }
        push @fields, $field;
    }

    return @fields;
}

###############################################################################
# Backup existing DB files
###############################################################################
sub db_backup_files {
    my $timestamp  = strftime("%Y%m%d_%H%M%S", localtime);
    my $backup_dir = "$dbpath/backup_$timestamp";

    print "[*] Creating backup in $backup_dir/\n";
    make_path($backup_dir);

    for my $file ($comvul_file, $corevul_file, $complist_file) {
        if (-f $file) {
            my $basename = $file;
            $basename =~ s/.*[\/\\]//;
            copy($file, "$backup_dir/$basename")
                or warn "    Warning: could not backup $basename: $!\n";
        }
    }
}

###############################################################################
# Write merged data to DB files
###############################################################################
sub db_write_comvul {
    # Sort by date (field index 2) using Schwartzian transform
    my @sorted = map  { $_->[1] }
                 sort { $a->[0] cmp $b->[0] }
                 map  {
                     my @f;
                     while ($_ =~ /\[(.*?)\]/g) { push @f, $1; }
                     [($f[2] // '0000-00-00'), $_]
                 } values %comvul_entries;

    open(my $fh, '>', $comvul_file) or die "Cannot write $comvul_file: $!\n";
    for my $line (@sorted) {
        print $fh "$line\n";
    }
    close($fh);
    print "[*] Wrote " . scalar(@sorted) . " entries to comvul.txt\n";
}

sub db_write_corevul {
    my @lines = values %corevul_entries;

    open(my $fh, '>', $corevul_file) or die "Cannot write $corevul_file: $!\n";
    for my $line (@lines) {
        print $fh "$line\n";
    }
    close($fh);
    print "[*] Wrote " . scalar(@lines) . " entries to corevul.txt\n";
}

sub db_write_componentslist {
    my @names = sort { lc($a) cmp lc($b) } keys %component_names;

    open(my $fh, '>', $complist_file) or die "Cannot write $complist_file: $!\n";
    for my $name (@names) {
        print $fh "$name\n";
    }
    close($fh);
    print "[*] Wrote " . scalar(@names) . " entries to componentslist.txt\n";
}
