#!/usr/bin/perl
use strict;
use warnings;
use POSIX qw(strftime);
use Fcntl qw(:DEFAULT :flock);

# ---------------- CONFIG ----------------
my $VERSION    = "1.2";

my $PINFILE    = "/tmp/pin.txt";      # used by OpenSSL pkcs11 engine in your setup
my $SLOT       = "9c";
my $KEYID      = "02";                # must match actual object id in token for openssl pkcs11:id
my $KEYALGO    = "ECCP384";           # consider ECCP521 if required by spec
my $PINPOLICY  = "always";
my $TOUCHPOLICY= "never";

my $SUBJ       = "/CN=Estonian Trusted List Scheme Operator/C=EE/O=Estonian Information System Authority";

# default destination (operator can change interactively)
my $dst_default = "/media/user/KINGSTON/cert";

# fingerprint algorithm used by this script
my $FP_ALGO = "sha256";

# Set to 1 ONLY for development; in production keep 0
my $DEV_FORCE_PUK = 0;                # if 1, uses "12345678" (NOT SAFE)
my $DEFAULT_PIN   = "123456";

my $SECSPERDAY = 24 * 60 * 60;

$ENV{"LD_LIBRARY_PATH"} = "/usr/local/lib";
$ENV{"OPENSSL_CONF"}    = "./openssl.conf";

# ---------------- UI / logging helpers ----------------
sub ts { return strftime("%Y-%m-%d %H:%M:%S", localtime); }
sub sayi { print STDOUT "[".ts()."] $_[0]\n"; }
sub ok   { print STDOUT "  [OK]   $_[0]\n"; }
sub warnm{ print STDOUT "  [WARN] $_[0]\n"; }
sub fail { print STDOUT "  [FAIL] $_[0]\n"; }

sub formattime {
  my @t = @_;
  return sprintf "%04d-%02d-%02d %02d:%02d:%02d", $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0];
}
sub formattimeopenssl {
  my @t = @_;
  return sprintf "%04d%02d%02d%02d%02d%02dZ", $t[5]+1900, $t[4]+1, $t[3], $t[2], $t[1], $t[0];
}

sub parsetime {
  my ($str) = @_;
  my $cmd = "bash -c \"date -d '$str UTC' +%s\"";
  my $ts = `$cmd 2>&1`;
  chomp($ts);
  return $ts;
}

sub askYesNo {
  my ($default) = @_;
  my $answer = <STDIN>;
  chomp($answer);
  $answer = $default if (!defined($answer) || $answer eq "");
  $answer = lc($answer);
  return $answer eq "y";
}

sub log_line {
  my ($ofs, $line) = @_;
  print $ofs "[".ts()."] $line\n";
}

sub run_cmd {
  my ($ofs, $step, $desc, $cmd, $mask) = @_;

  print STDOUT "\n==== [$step] $desc ====\n";
  log_line($ofs, "==== [$step] $desc ====");
  log_line($ofs, "CMD: " . (defined $mask ? $mask : $cmd));

  my $out = `$cmd 2>&1`;
  my $rc  = $? >> 8;

  if (length $out) {
    # Keep output in log; show minimal on screen unless failure
    print $ofs $out;
  }

  if ($rc != 0) {
    print STDOUT "==== FAILED (exit=$rc) ====\n";
    print STDOUT $out if $out;
    log_line($ofs, "RESULT: FAILED (exit=$rc)");
    die "Step failed: $desc (exit=$rc)\n";
  }

  print STDOUT "==== SUCCESS ====\n";
  log_line($ofs, "RESULT: SUCCESS");
}

sub run_cmd_capture_single {
  my ($ofs, $step, $desc, $cmd) = @_;
  print STDOUT "\n==== [$step] $desc ====\n";
  log_line($ofs, "==== [$step] $desc ====");
  log_line($ofs, "CMD: $cmd");

  my $out = `$cmd 2>&1`;
  my $rc  = $? >> 8;

  print $ofs $out if length $out;

  if ($rc != 0 || !defined($out) || $out eq "") {
    print STDOUT "==== FAILED (exit=$rc) ====\n";
    print STDOUT $out if $out;
    log_line($ofs, "RESULT: FAILED (exit=$rc)");
    die "Step failed: $desc\n";
  }

  print STDOUT "==== SUCCESS ====\n";
  log_line($ofs, "RESULT: SUCCESS");
  chomp($out);
  return $out;
}

sub require_cmd {
  my ($name) = @_;
  my $rc = system("command -v $name >/dev/null 2>&1");
  return $rc == 0;
}

sub verify_yubikey {
  my $out = qx(./yubico-piv-tool --action=status);
  my @lines = split("\n", $out);
  foreach(@lines) {
    return 0 if substr($_, 0, 4) eq "Slot";
  }
  return 1;
}

# ---------------- secret handling ----------------
my $TTY_ECHO_DISABLED = 0;

sub disable_echo {
  system("stty -echo");
  $TTY_ECHO_DISABLED = 1;
}

sub enable_echo {
  system("stty echo");
  $TTY_ECHO_DISABLED = 0;
}

END {
  # Ensure terminal echo is restored on any exit path
  if ($TTY_ECHO_DISABLED) {
    eval { enable_echo(); };
  }
  # Best-effort cleanup of PINFILE
  if (-e $PINFILE) {
    system("shred -u '$PINFILE' >/dev/null 2>&1");
  }
}

sub write_pinfile_secure {
  my ($pin) = @_;
  sysopen(my $fh, $PINFILE, O_WRONLY|O_CREAT|O_TRUNC, 0600) or die "Cannot create $PINFILE\n";
  print $fh $pin;
  close $fh;
}

sub cleanup_pinfile {
  if (-e $PINFILE) {
    system("shred -u '$PINFILE' >/dev/null 2>&1");
  }
}

sub gen_random_puk_8digits {
  # Generate an 8-digit numeric string; good enough for this usage
  open my $ifs, "<", "/dev/urandom" or die "Cannot open /dev/urandom\n";
  my $n = 0;
  for (1..4) {
    $n = ($n << 8) + ord(getc($ifs));
  }
  close $ifs;
  $n = $n % 100000000; # 8 digits
  return sprintf("%08d", $n);
}

sub gen_random_mgm_key {
  # Generate an 48-hex-digit numeric string
  open my $ifs, "<", "/dev/urandom" or die "Cannot open /dev/urandom\n";
  my $str = "";
  for (1..24) {
    $str .= sprintf("%02x", ord(getc($ifs)));
  }
  close $ifs;
  return $str;
}

# ---------------- main ----------------
my $PROGTITLE = "EISA Certificate generation tool $VERSION";
print STDOUT "$PROGTITLE\n\n";

# Preflight
sayi("Preflight checks");
if ($> != 0) {
  ok("Not running as root. This is usually OK if yubico-piv-tool and output paths are accessible.");
}

for my $tool ("openssl", "sha256sum", "date", "stty") {
  if (!require_cmd($tool)) {
    die "Missing required tool in PATH: $tool\n";
  }
}
ok("Required OS tools present");

if (!-f "./openssl.conf") {
  warnm("openssl.conf not found in current directory; OPENSSL_CONF=./openssl.conf may fail.");
} else {
  ok("openssl.conf present");
}

if (!-x "./yubico-piv-tool") {
  warnm("./yubico-piv-tool not executable or not found in current directory. Script expects it here.");
} else {
  ok("yubico-piv-tool present");
}

if (!verify_yubikey()) {
  warnm("Some YubiKey slots are not empty. Make sure that this is intended.");
} else {
  ok("All YubiKey slots are empty");
}

# Input parameters
my $dst   = $dst_default;
my $fname = "test";
my $start = time();
my $days  = 365;

do {
  # Destination path
  my $path;
  do {
    printf "Enter the destination directory [%s]: ", $dst;
    $path = <STDIN>;
    chomp($path);
    $path = $dst if !$path;

    $path .= "/" if substr($path, -1) ne "/";

    if (!-d $path) {
      print STDOUT "Path does not exist, create? (Y/n): ";
      if (askYesNo("y")) {
        system("mkdir -p '$path'") == 0 or warnm("Could not create directory: $path");
      }
    } elsif (!-w $path) {
      warnm("Path is not writable: $path");
    }
  } until (-d $path && -w $path);
  $dst = $path;

  # Certificate filename
  print STDOUT "Enter certificate filename (.crt will be added) [$fname]: ";
  my $str = <STDIN>;
  chomp($str);
  $fname = $str if $str;

  # Start time
  printf STDOUT "Input the new UTC start time [%s]: ", formattime(gmtime($start));
  $str = <STDIN>;
  chomp($str);
  if ($str) {
    my $t = parsetime($str);
    if ($t !~ /^\d+$/) {
      warnm("Could not parse date; keeping previous start time.");
    } else {
      $start = $t;
    }
  }

  # Validity period
  print STDOUT "Enter the validity period in days [$days]: ";
  $str = <STDIN>;
  chomp($str);
  $days = $str if ($str && $str =~ /^\d+$/);

  # Confirmation
  printf STDOUT "\nCreate a certificate with the following parameters:\n";
  printf STDOUT "  Destination path:       $dst\n";
  printf STDOUT "  Certificate filename:   $fname (.crt .pub .$FP_ALGO)\n";
  printf STDOUT "  Valid from (UTC):       %s\n", formattime(gmtime($start));
  printf STDOUT "  Validity period (days): $days\n";
  printf STDOUT "  Valid to (UTC):         %s\n", formattime(gmtime($start + $days * $SECSPERDAY));
  print STDOUT "Is this correct? (Y/n): ";
} until (askYesNo("y"));

# Derived filenames
my $keyfile     = "$dst$fname.pub";
my $csrfile     = "/tmp/$fname.csr";
my $certfile    = "$dst$fname.crt";
my $certfpfile  = "$dst$fname.$FP_ALGO";           # fingerprint from openssl -fingerprint
my $filefpfile  = "$certfile.$FP_ALGO";            # file hash (sha256sum of cert file)
my $logfile     = "$dst$fname.log";

# Start logging
open my $ofs, ">", $logfile or die "Cannot open log file: $logfile\n";
log_line($ofs, $PROGTITLE);
log_line($ofs, "Parameters:");
log_line($ofs, "  Destination: $dst");
log_line($ofs, "  Name:        $fname.crt");
log_line($ofs, "  Valid from:  " . formattime(gmtime($start)) . " UTC");
log_line($ofs, "  Days:        $days");
log_line($ofs, "  Valid to:    " . formattime(gmtime($start + $days*$SECSPERDAY)) . " UTC");
log_line($ofs, "  Slot:        $SLOT");
log_line($ofs, "  KeyID:       $KEYID");
log_line($ofs, "  KeyAlgo:     $KEYALGO");
log_line($ofs, "  PinPolicy:   $PINPOLICY");
log_line($ofs, "  TouchPolicy: $TOUCHPOLICY");

sayi("Logging to: $logfile");
print STDOUT "\n";

# 1) Verify default PIN
run_cmd($ofs, "1/10", "Verify default PIN on slot $SLOT",
  "./yubico-piv-tool --slot=$SLOT --action=verify-pin --pin=$DEFAULT_PIN",
  "./yubico-piv-tool --slot=$SLOT --action=verify-pin --pin=XXX"
);

# 2) Ask for new PIN parts
print STDOUT "\n";
print STDOUT "Enter the FIRST part of PIN: ";
disable_echo();
my $pin1 = <STDIN>; chomp($pin1);
print STDOUT "\nEnter the SECOND part of PIN: ";
my $pin2 = <STDIN>; chomp($pin2);
enable_echo();
print STDOUT "\n";

if (!defined($pin1) || !defined($pin2) || $pin1 eq "" || $pin2 eq "") {
  die "PIN parts cannot be empty\n";
}
my $pin = $pin1 . $pin2;

# 3) Set new PIN
run_cmd($ofs, "2/10", "Set new PIN for slot $SLOT",
  "./yubico-piv-tool --slot=$SLOT --action=change-pin --pin=$DEFAULT_PIN --new-pin='$pin'",
  "./yubico-piv-tool --slot=$SLOT --action=change-pin --pin=XXX --new-pin=XXX"
);

# 4) Verify new PIN
run_cmd($ofs, "3/10", "Verify new PIN",
  "./yubico-piv-tool --slot=$SLOT --action=verify-pin --pin='$pin'",
  "./yubico-piv-tool --slot=$SLOT --action=verify-pin --pin=XXX"
);

# 5) Generate and set PUK
my $puk = $DEV_FORCE_PUK ? "12345678" : gen_random_puk_8digits();
if ($DEV_FORCE_PUK) {
  warnm("DEV_FORCE_PUK is enabled. PUK is hardcoded to 12345678. Disable for production.");
  log_line($ofs, "WARN: DEV_FORCE_PUK enabled; PUK=12345678");
} else {
  log_line($ofs, "PUK generated (value not printed)");
}

run_cmd($ofs, "4/10", "Set new PUK",
  "./yubico-piv-tool --slot=$SLOT --action=change-puk --pin=12345678 --new-pin='$puk'",
  "./yubico-piv-tool --slot=$SLOT --action=change-puk --pin=XXX --new-pin=XXX"
);

# 5.1) generate and set random management key
my $mgmkey = $DEV_FORCE_PUK ? "010203040506070801020304050607080102030405060708" : gen_random_mgm_key();
run_cmd($ofs, "4.1/10", "Set new Management key",
  "./yubico-piv-tool --action=set-mgm-key --key=010203040506070801020304050607080102030405060708 --new-key='$mgmkey'",
  "./yubico-piv-tool --action=set-mgm-key --key=XXX --new-key=XXX"
);

# 6) Generate keypair in YubiKey, export public key
run_cmd($ofs, "5/10", "Generate keypair (algo=$KEYALGO) and export public key",
  "./yubico-piv-tool --slot=$SLOT --action=generate --algorithm=$KEYALGO --key='$mgmkey' --pin='$pin' --pin-policy=$PINPOLICY --touch-policy=$TOUCHPOLICY --output='$keyfile'",
  "./yubico-piv-tool --slot=$SLOT --action=generate --algorithm=$KEYALGO --key=XXX --pin=XXX --pin-policy=$PINPOLICY --touch-policy=$TOUCHPOLICY --output='$keyfile'"
);

# 7) Generate CSR
write_pinfile_secure($pin);

run_cmd($ofs, "6/10", "Generate CSR",
  "openssl req -new -key pkcs11:id=%$KEYID -out '$csrfile' -sha512 -subj '$SUBJ'",
  "openssl req -new -key pkcs11:id=%$KEYID -out '$csrfile' -sha512 -subj '$SUBJ' (PINFILE used)"
);

# 8) Self-sign certificate using OpenSSL CA
# Prepare index and dates
if (-f "index") { run_cmd($ofs, "6.1/10", "Remove old index file", "rm -f index"); }
run_cmd($ofs, "6.2/10", "Create index file", "touch index");

my $nb = formattimeopenssl(gmtime($start));
my $na = formattimeopenssl(gmtime($start + $days * $SECSPERDAY));

run_cmd($ofs, "7/10", "Create self-signed certificate",
  "openssl ca -selfsign -create_serial -keyfile pkcs11:id=%$KEYID -out '$certfile' -startdate $nb -enddate $na -extensions v3_ca -in '$csrfile' -preserveDN -batch -notext",
  "openssl ca -selfsign ... -keyfile pkcs11:id=%$KEYID -out '$certfile' (PINFILE used)"
);

# Cleanup sensitive temp
cleanup_pinfile();
unlink $csrfile if -f $csrfile;

# 9) Import certificate
run_cmd($ofs, "8/10", "Import certificate to YubiKey slot $SLOT",
  "./yubico-piv-tool --slot=$SLOT --action=import-certificate --key='$mgmkey' --input='$certfile'",
  "./yubico-piv-tool --slot=$SLOT --action=import-certificate --key=XXX --input='$certfile'"
);

# 10) Fingerprints
print STDOUT "\n==== [9/10] Creating fingerprints ($FP_ALGO) ====\n";
log_line($ofs, "==== [9/10] Creating fingerprints ($FP_ALGO) ====");

my $fp_out = run_cmd_capture_single($ofs, "9.1/10", "Certificate fingerprint (openssl -fingerprint)",
  "openssl x509 -in '$certfile' -noout -$FP_ALGO -fingerprint"
);

# Parse openssl output like: "SHA256 Fingerprint=AA:BB:..."
my ($label, $csum) = split(/=/, $fp_out, 2);
$csum //= "";
$csum =~ s/\s+$//;

if ($csum eq "") {
  die "Could not parse certificate fingerprint output: $fp_out\n";
}
open my $cfh, ">", $certfpfile or die "Cannot write $certfpfile\n";
print $cfh "$csum\n";
close $cfh;
ok("Certificate fingerprint saved: $certfpfile");
print STDOUT "Certificate $FP_ALGO: $csum\n";

my $filehash_out = run_cmd_capture_single($ofs, "9.2/10", "Certificate file hash (sha256sum)",
  "$FP_ALGO"."sum '$certfile'"
);

# sha256sum output: "<hex>  <file>"
my ($hexsum) = split(/\s+/, $filehash_out);
if (!$hexsum) {
  die "Could not parse $FP_ALGO sum output: $filehash_out\n";
}
open my $ffh, ">", $filefpfile or die "Cannot write $filefpfile\n";
print $ffh "$hexsum\n";
close $ffh;
ok("Certificate file hash saved: $filefpfile");
print STDOUT "$certfile $FP_ALGO: $hexsum\n";

# 11) Test signing
print STDOUT "\n==== [10/10] Testing signing ====\n";
log_line($ofs, "==== [10/10] Testing signing ====");

my $TOSIGNFILE = "/tmp/sign-test.txt";
my $SIGNFILE   = "/tmp/sign-test.sig";
my $PUBKEYFILE = "/tmp/pubkey.pem";

write_pinfile_secure($pin);

run_cmd($ofs, "10.1/10", "Create test file",
  "bash -c \"echo 'Allkirjastamise test' > '$TOSIGNFILE'\""
);

run_cmd($ofs, "10.2/10", "Sign test file",
  "openssl dgst -$FP_ALGO -sign pkcs11:id=%$KEYID -out '$SIGNFILE' '$TOSIGNFILE'",
  "openssl dgst -$FP_ALGO -sign pkcs11:id=%$KEYID -out '$SIGNFILE' '$TOSIGNFILE' (PINFILE used)"
);

run_cmd($ofs, "10.3/10", "Extract public key from certificate",
  "openssl x509 -in '$certfile' -pubkey -noout > '$PUBKEYFILE'"
);

run_cmd($ofs, "10.4/10", "Verify signature",
  "openssl dgst -$FP_ALGO -verify '$PUBKEYFILE' -signature '$SIGNFILE' '$TOSIGNFILE'"
);

cleanup_pinfile();

unlink $TOSIGNFILE if -f $TOSIGNFILE;
unlink $SIGNFILE   if -f $SIGNFILE;
unlink $PUBKEYFILE if -f $PUBKEYFILE;

# Finish
log_line($ofs, "Certificate fingerprint ($FP_ALGO): $csum");
log_line($ofs, "Certificate file hash ($FP_ALGO): $hexsum");
log_line($ofs, "Finished at " . formattime(gmtime(time())) . " UTC");
log_line($ofs, "Certificate generation succeeded");
close $ofs;

print STDOUT "\nAll steps completed successfully\n";
print STDOUT "Public key:                       $keyfile\n";
print STDOUT "Certificate:                      $certfile\n";
print STDOUT "Certificate fp ($FP_ALGO):         $certfpfile\n";
print STDOUT "Certificate FILE hash ($FP_ALGO):  $filefpfile\n";
print STDOUT "Log file:                         $logfile\n";
print STDOUT "\nCertificate generated\n";
