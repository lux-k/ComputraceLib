package Computrace;
use Moose;
use Mojo::UserAgent;
use Data::Dumper;
use POSIX 'strftime';
use MIME::Base64;
use Digest::SHA qw(sha256_hex hmac_sha256 hmac_sha256_hex);

has HOST		=> (is => 'rw', trigger => \&after_host_change);
has USER		=> (is => 'rw');
has PASSWORD	=> (is => 'rw');
has DEBUG		=> (is => 'rw');
has HOSTNAME	=> (is => 'rw');
has datet		=>	(is => 'rw');
has datep		=>	(is => 'rw');
has client		=> (is => 'rw');

use constant HASHING_ALGORITHM => 'ABS1-HMAC-SHA-256';
use constant REGION => 'cadc';
use constant SIGVERSION => 'abs1';
use constant CONTENT_TYPE => 'application/json';
use constant APIVERSION => 'v2';

sub BUILD {
	my $self = shift;
	$self->HOST('https://api.absolute.com/') unless defined $self->HOST;
	$self->USER('admin') unless defined $self->USER;
	$self->PASSWORD('admin') unless defined $self->PASSWORD;
	$self->DEBUG(0) unless defined $self->DEBUG;
}

sub after_host_change {
	my $self = shift;
	my $h = $self->HOST;
	$h =~ m#/([^\/]+)/#;
	$self->HOSTNAME($1);
}	

sub GetAllDevices {
	my $self = shift;
	$self->Get('reporting/devices','');
}

sub GetDevicesBySerial {
	my $self = shift;
	my $val = $self->Encode(shift);
	return $self->Get('reporting/devices',"%24filter=substringof%28%27$val%27%2C%20serial%29%20eq%20true");
}

sub GetDevicesByESN {
	my $self = shift;
	my $val = $self->Encode(shift);
	return $self->Get('reporting/devices',"%24filter=substringof%28%27$val%27%2C%20esn%29%20eq%20true");
}

sub Encode {
	my $self = shift;
	my $input = shift;
	$input =~ s/([:\/\?#\[\]\@!\$&'\(\)\*\+,;=])/sprintf("%%%02d",ord($1))/ge;
	return $input;
}	

sub GetDevicesByMachineName {
	my $self = shift;
	my $val = $self->Encode(shift);
	return $self->Get('reporting/devices',"%24filter=substringof%28%27$val%27%2C%20systemName%29%20eq%20true");
}

sub SetDates {
	my $self = shift;
	my @now = gmtime();
	$self->datet(strftime("%Y%m%dT%H%M%SZ", @now));
	$self->datep(strftime("%Y%m%d", @now));
}

sub Post {
	my $self = shift;
	my $method = shift;
	my $values = shift;
	my $client = $self->CreateClient;
	my $headers = {};
	$headers->{'X-SecurityCenter'} = $self->token if $self->token;
	return $client->post($self->HOST . $method => $headers => json => $values);
}

sub MakeCredScope {
	my $self = shift;
	return $self->datep . "/" . Computrace->REGION . '/' . Computrace->SIGVERSION;
}

sub Get {
	my $self = shift;
	my $uri = Computrace->APIVERSION . "/" . shift;
	
	my $query = shift ;
	my $client = $self->CreateClient;

	$self->SetDates;

	my @canlines = (
		'GET',
		'/'.$uri,
		$query,
		'host:' . $self->HOSTNAME,
		'content-type:application/json',
		"x-abs-date:" . $self->datet,
		sha256_hex(''));
	my $canreq = join("\n", @canlines);	
	print "Canreq = $canreq\n\n" if $self->DEBUG;
	
	return $client->get($self->HOST . $uri . ($query && "?$query" || '') => $self->MakeHeaders($self->SignSigningStr($self->MakeSigningStr($canreq))))->result->json;
}

sub MakeHeaders {
	my $self = shift;
	my $signature = shift;
	my $headers = {};
	$headers->{'Host'} = $self->HOSTNAME;
	$headers->{'Content-Type'} = Computrace->CONTENT_TYPE;
	$headers->{'X-Abs-Date'} = $self->datet;
	$headers->{'Authorization'} = Computrace->HASHING_ALGORITHM . " Credential=" . $self->USER . "/" . $self->MakeCredScope . ", SignedHeaders=host;content-type;x-abs-date, Signature=$signature";
	print "Authline: " . $headers->{'Authorization'} . "\n" if $self->DEBUG;
	return $headers;
}	

sub MakeSigningStr {
	my $self = shift;
	my $canreq = shift;
	my @signlines = (
		Computrace->HASHING_ALGORITHM,
		$self->datet,
		$self->MakeCredScope,
		sha256_hex($canreq));
	my $signingstr = join("\n", @signlines);
	print "Sign = $signingstr\n\n" if $self->DEBUG;
	return $signingstr;
}

sub SignSigningStr {
	my $self = shift;
	my $signingstr = shift;
	my $kfun = 'ABS1' . $self->PASSWORD;
	utf8::encode($kfun);
	my $kdate = hmac_sha256($self->datep, $kfun);
	my $ksigning = hmac_sha256("abs1_request", $kdate);
	my $signature = hmac_sha256_hex($signingstr, $ksigning);
	return $signature;
}	

sub Delete {
	my $self = shift;
	my $method = shift;
	my $values = shift || {};
	my $client = $self->CreateClient;
	my $headers = {};
	$headers->{'X-SecurityCenter'} = $self->token if $self->token;
	return $client->delete($self->HOST . $method => $headers => json => $values);
}

sub Patch {
	my $self = shift;
	my $method = shift;
	my $values = shift || {};
	my $client = $self->CreateClient;
	my $headers = {};
	$headers->{'X-SecurityCenter'} = $self->token if $self->token;
	return $client->patch($self->HOST . $method => $headers => json => $values);
}

sub CreateClient {
	my $self = shift;
	
	return $self->client if $self->client;

	$ENV{PERL_LWP_SSL_VERIFY_HOSTNAME} = 0;

	my $client = Mojo::UserAgent->new;
	$client->cookie_jar(Mojo::UserAgent::CookieJar->new);
	$self->client($client);

	return $client;
}

END;

1;
