#!/usr/bin/perl
use strict;
use warnings;
use POSIX qw(strftime);
use File::Spec;

$ENV{"LC_ALL"} = "et_EE.UTF-8";

# ---------- helpers ----------
sub ts { return strftime("%Y-%m-%d %H:%M:%S", localtime); }

sub sayi { print STDOUT "[" . ts() . "] $_[0]\n"; }
sub ok   { print STDOUT "  [OK]   $_[0]\n"; }
sub warnm{ print STDOUT "  [WARN] $_[0]\n"; }
sub fail { print STDOUT "  [FAIL] $_[0]\n"; }

sub die_fail {
  my ($msg, $details) = @_;
  fail($msg);
  print STDOUT "         $details\n" if defined $details && length $details;
  die "$msg\n";
}

sub run_cmd {
  my ($label, $cmd) = @_;
  print STDOUT "  [RUN]  $label\n";
  print STDOUT "         $cmd\n";

  # Capture both stdout and stderr for better diagnostics
  my $out = `$cmd 2>&1`;
  my $rc  = $? >> 8;

  if ($rc != 0) {
    die_fail($label, "exit=$rc; output:\n$out");
  }
  ok($label);
  return $out;
}

sub file_exists_or_die {
  my ($path, $what) = @_;
  if (!-e $path) {
    die_fail("Missing required file", "$what not found: $path");
  }
}

sub dir_exists_or_die {
  my ($path, $what) = @_;
  if (!-d $path) {
    die_fail("Missing required directory", "$what not found: $path");
  }
}

sub append_line_if_missing {
  my ($file, $line) = @_;
  my $exists = 0;

  if (-e $file) {
    open my $fh, "<", $file or die_fail("Cannot read $file", $!);
    while (my $l = <$fh>) {
      chomp $l;
      if ($l eq $line) { $exists = 1; last; }
    }
    close $fh;
  }

  if ($exists) {
    ok("Line already present in $file");
    return;
  }

  open my $fh, ">>", $file or die_fail("Cannot write $file", $!);
  print $fh "$line\n";
  close $fh;
  ok("Appended line to $file");
}

sub ensure_symlink {
  my ($target, $linkpath) = @_;

  # If link exists and points correctly, keep it
  if (-l $linkpath) {
    my $cur = readlink($linkpath);
    if (defined $cur && $cur eq $target) {
      ok("Symlink exists: $linkpath -> $target");
      return;
    }
    # wrong target, replace
    run_cmd("Replacing symlink $linkpath", "rm -f '$linkpath'");
  } elsif (-e $linkpath) {
    # exists but not a symlink
    run_cmd("Removing non-symlink path $linkpath", "rm -f '$linkpath'");
  }

  run_cmd("Creating symlink $linkpath -> $target", "ln -s '$target' '$linkpath'");
}

# ---------- banner ----------
print STDOUT "\n";
sayi("install.pl starting");
sayi("Working directory: " . `pwd`);
print STDOUT "\n";

# ---------- preflight ----------
sayi("Preflight checks");

# Must run as root
if ($> != 0) {
  die_fail("Must be run as root (use sudo)", "Current euid=$>");
}
ok("Running as root");

my $user = $ENV{"SUDO_USER"} // "";
if (!$user) {
  # Fallback: best effort
  $user = $ENV{"USER"} // "";
  warnm("SUDO_USER not set; using USER=$user") if $user;
}
if (!$user) {
  die_fail("Cannot determine target user", "SUDO_USER/USER not set");
}
ok("Target user: $user");

my $home = (getpwnam($user))[7];
if (!$home || !-d $home) {
  die_fail("Cannot resolve home directory for user", "user=$user home=$home");
}
ok("Target home: $home");

# Required inputs present in current directory
file_exists_or_die("libccid_1.5.5-1_arm64.deb", "libccid .deb");
file_exists_or_die("pcscd_2.0.3-1build1_arm64.deb", "pcscd .deb");
dir_exists_or_die("lib", "library directory");
file_exists_or_die("lib/libykcs11.so.2.7.2", "YubiKey PKCS11 library");
file_exists_or_die("lib/libykpiv.so.2.7.2", "YubiKey PIV library");
file_exists_or_die("ykman-users.rules", "polkit rules file");
dir_exists_or_die("cert", "cert directory");
ok("All required input files present");

print STDOUT "\n";

# ---------- step 1: install packages ----------
sayi("Step 1/5: Installing packages");
run_cmd("Installing libccid", "dpkg -i ./libccid_1.5.5-1_arm64.deb");
run_cmd("Installing pcscd",   "dpkg -i ./pcscd_2.0.3-1build1_arm64.deb");
print STDOUT "\n";

# ---------- step 2: install libraries + symlinks ----------
sayi("Step 2/5: Installing libraries");
run_cmd("Copying libraries to /usr/local/lib", "cp -v -d lib/* /usr/local/lib/");
run_cmd("Refreshing dynamic linker cache", "ldconfig");

ensure_symlink("/usr/local/lib/libykcs11.so.2.7.2", "/usr/local/lib/libykcs11.so.2");
ensure_symlink("/usr/local/lib/libykcs11.so.2.7.2", "/usr/local/lib/libykcs11.so");
ensure_symlink("/usr/local/lib/libykpiv.so.2.7.2",  "/usr/local/lib/libykpiv.so.2");
ensure_symlink("/usr/local/lib/libykpiv.so.2.7.2",  "/usr/local/lib/libykpiv.so");

# Prefer /etc/ld.so.conf.d over LD_LIBRARY_PATH, but keep your existing behavior.
# We add both, but avoid duplicates.
run_cmd("Ensuring /usr/local/lib is in ld.so.conf.d", "sh -c \"echo '/usr/local/lib' > /etc/ld.so.conf.d/local-usrlib.conf\"");
run_cmd("Refreshing dynamic linker cache (post-config)", "ldconfig");

append_line_if_missing("/etc/bash.bashrc", 'export LD_LIBRARY_PATH=/usr/local/lib');

print STDOUT "\n";

# ---------- step 3: enable user access to pcsc via polkit ----------
sayi("Step 3/5: Enabling access to PCSC service");
run_cmd("Copying polkit rule", "cp -v ./ykman-users.rules /usr/share/polkit-1/rules.d/");
print STDOUT "\n";

# ---------- step 4: copy certificate generation scripts ----------
sayi("Step 4/5: Installing certificate generation scripts");
run_cmd("Copying cert directory to $home", "cp -r ./cert '$home/'");
run_cmd("Fixing ownership on $home/cert", "chown -R '$user:$user' '$home/cert'");
append_line_if_missing("$home/.profile", 'export LD_LIBRARY_PATH=/usr/local/lib');
print STDOUT "\n";

# ---------- step 5: basic sanity checks ----------
sayi("Step 5/5: Sanity checks");
run_cmd("pcscd service status (non-fatal output shown below)", "systemctl status pcscd --no-pager | head -n 15");
print STDOUT "\n";

# ---------- summary ----------
sayi("Installation complete");
print STDOUT "\nSummary:\n";
print STDOUT "  - Target user:  $user\n";
print STDOUT "  - Cert scripts: $home/cert\n";
print STDOUT "  - Libraries:    /usr/local/lib (symlinks created; ldconfig updated)\n";
print STDOUT "  - PCSC policy:  /usr/share/polkit-1/rules.d/ykman-users.rules\n";
print STDOUT "\n";
print STDOUT "Next: You can disconnect the USB drive and continue the ceremony on the Raspberry Pi (offline).\n\n";
