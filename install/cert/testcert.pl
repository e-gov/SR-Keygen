#!/usr/bin/perl

use strict;
use warnings;
use POSIX;

my $VERSION = "1.0";

my $PINFILE = "/tmp/pin.txt";
# NB! If changing slot keyid should be changed too
my $SLOT = "9c";
my $KEYID = "02";
my $KEYALGO = "ECCP384";

$ENV{"LD_LIBRARY_PATH"} = "/usr/local/lib";
$ENV{"OPENSSL_CONF"} = "./openssl.conf";

sub formattime {
  my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = @_;
  return sprintf "%04d-%02d-%02d %02d:%02d:%02d", $year + 1900, $mon + 1, $mday, $hour, $min, $sec;
}

sub execute {
  my $ofs = $_[0];
  my $cmd = $_[1];
  my $text = $_[2];
  my $print = $cmd;
  if ($_[3]) {
    $print = sprintf $cmd, "XXX";
    $cmd = sprintf $cmd, $_[3];
  }
  printf STDOUT "\n==== $text ====\n";
  printf $ofs "\n%s %s\n", formattime(gmtime(time())), $text;
  printf $ofs "  %s\n", $print;
  my $result = system $cmd;
  select STDOUT;
  if ($result) {
    printf STDOUT "==== FAILED ====\n";
    printf $ofs "%s FAILED\n", formattime(gmtime(time()));
    return 0;
  } else {
    printf STDOUT "==== SUCCESS ====\n";
    printf $ofs "%s Success\n", formattime(gmtime(time()));
    return 1;
  }
}

sub executex {
  my $ofs = $_[0];
  my $cmd = $_[1];
  my $text = $_[2];
  my $print = $cmd;
  if ($_[3]) {
    $print = sprintf $cmd, "XXX";
    $cmd = sprintf $cmd, $_[3];
  }
  printf STDOUT "\n==== $text ====\n";
  printf $ofs "\n%s %s\n", formattime(gmtime(time())), $text;
  printf $ofs "  %s\n", $print;
  my $result = qx/$cmd/;
  chomp($result);
  select STDOUT;
  if (!$result) {
    printf STDOUT "==== FAILED ====\n";
    printf $ofs "%s FAILED\n", formattime(gmtime(time()));
  } else {
    printf STDOUT "==== SUCCESS ====\n";
    printf $ofs "%s Success\n", formattime(gmtime(time()));
  }
  return $result;
}

print STDOUT "EISA Certificate testing tool $VERSION\n";
print STDOUT "\n";
my ($sec,$min,$hour,$mday,$mon,$year,$wday,$yday,$isdst) = localtime();
my $fname = sprintf "test-%04d%02d%02d%02d%02d%02d.log", $year + 1900, $mon + 1, $mday, $hour, $min, $sec;
open my $ofs, ">$fname" or die $!;
printf $ofs "EISA certificate signing test\n";
printf $ofs "Started at: %s\n", formattime(gmtime());
printf $ofs "Key at YubiKey slot 9c\n";

# Ask and set the new PIN
system "stty -echo";
print STDOUT "Enter the FIRST part of PIN: ";
my $pin1 = <STDIN>;
print STDOUT "\n";
chomp $pin1;
print STDOUT "Enter the SECOND part of PIN: ";
my $pin2 = <STDIN>;
print STDOUT "\n";
chomp $pin2;
system "stty echo";

my $pin = $pin1.$pin2;
execute $ofs, "./yubico-piv-tool --slot=$SLOT --action=verify-pin --pin=%s", "Verifying PIN", $pin or die "Failed to verify PIN";

my $TOSIGNFILE = "/tmp/sign-test.txt";
my $SIGNFILE = "/tmp/sign-test.sig";
my $CERTFILE = "/tmp/sign-test.crt";
my $PUBKEYFILE = "/tmp/sign-test.pub";

# Extract certificate
execute $ofs, "./yubico-piv-tool --slot=$SLOT --action=read-certificate --out=$CERTFILE", "Extracting certificate" or die "Cannot extract certificate";
# Save pin for OpenSSL
system "echo $pin > $PINFILE";
my $result = execute $ofs, "echo \"Allkirjastamise test\" > $TOSIGNFILE", "Creating test file";
if ($result) {$result = execute $ofs, "openssl dgst -sha256 -sign pkcs11:id=%$KEYID -out $SIGNFILE $TOSIGNFILE", "Signing test file";}
if ($result) {$result = execute $ofs, "openssl x509 -in $CERTFILE -pubkey -noout > $PUBKEYFILE", "Extracting public key";}
if ($result) {$result = execute $ofs, "openssl dgst -sha256 -verify $PUBKEYFILE -signature $SIGNFILE $TOSIGNFILE", "Verifying signature";}
# Remove PIN file
system "shred $PINFILE;rm $PINFILE";
if (!$result) {die "Test failed";}

my $fp = executex $ofs, "openssl x509 -in $CERTFILE -noout -sha256 -fingerprint", "Get certificate fingerprint";
if (!$fp) {die "Cannot generate certificate fingerprint";}

execute $ofs, "rm $TOSIGNFILE $SIGNFILE $CERTFILE $PUBKEYFILE", "Remove temporary files" or die "Cannot remove temporary files";

printf $ofs "\nCertificate fingerprint\n";
printf $ofs "%s\n", $fp;
printf $ofs "\nSigning successful\n";
close $ofs;

print STDOUT "\nCertificate fingerprint\n";
printf STDOUT "%s\n", $fp;

#Finished
print STDOUT "\nSigning successful\n";
