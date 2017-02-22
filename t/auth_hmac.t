use strict;
use warnings;
use Test::More;
use Test::Mock::LWP::Dispatch;
use HTTP::Response;
use WWW::JSON;
use JSON::XS;
use URI;
use URI::QueryParam;

use MIME::Base64 qw( decode_base64 encode_base64 );
use Digest::SHA qw(sha256);
use Digest::HMAC qw(hmac);

my $creds = {
    api_key_id    => 'api_key_id',
    api_secret    => 'api_secret'
};

my $json    = JSON::XS->new;
my $fake_ua = LWP::UserAgent->new;
$fake_ua->map(
    'http://localhost/get/request?abc=123',
    sub {
        my $req = shift;
        my $method = $req->method;
        my $authorization = $req->header('Authorization');
        my ( $type, $keypair, $signaturepair, $datepair ) = split '; ' => $authorization;
        
        is $type, 'HHMAC', 'authorization type is correct';
        my ( undef, $key ) = split '=' => $keypair;
        my ( undef, $signature ) = split 'signature=' => $signaturepair; 
        my ( undef, $date ) = split '=' => $datepair;
             
        is $key, $creds->{api_key_id}, 'api_key_id is correct';

        my $canonical_request = join '' => $req->method, $req->uri, $date;
        my $secret = decode_base64( $creds->{api_secret} );
        my $computed_signature = encode_base64 hmac( $canonical_request, $secret, \&sha256 );
        chomp $computed_signature;

        is $computed_signature, $signature, 'computed signature matches Authorization header';

        return HTTP::Response->new( 200, 'OK', undef,
            $json->encode( { success => 'get request working' } ) );
    }
);
$fake_ua->map(
    'http://localhost/post/request',
    sub {
        my $req = shift;
        my $method = $req->method;
        my $authorization = $req->header('Authorization');
        my ( $type, $keypair, $signaturepair, $datepair ) = split '; ' => $authorization;
        
        is $type, 'HHMAC', 'authorization type is correct';
        my ( undef, $key ) = split '=' => $keypair;
        my ( undef, $signature ) = split 'signature=' => $signaturepair; 
        my ( undef, $date ) = split '=' => $datepair;
             
        is $key, $creds->{api_key_id}, 'api_key_id is correct';

        my $canonical_request = join '' => $req->method, $req->uri, $date;
        $canonical_request .= join '' => $req->header('Content-Type'), $req->content;

        my $secret = decode_base64( $creds->{api_secret} );
        my $computed_signature = encode_base64 hmac( $canonical_request, $secret, \&sha256 );
        chomp $computed_signature;

        is $computed_signature, $signature, 'computed signature matches Authorization header';

        return HTTP::Response->new( 200, 'OK', undef,
            $json->encode( { success => 'post request working' } ) );
    }
);

ok my $wj = WWW::JSON->new(
    ua             => $fake_ua,
    base_url       => 'http://localhost/',
    authentication => { HMAC => $creds },
  ),
  'initialized www json with hmac creds';

ok my $get = $wj->get( '/get/request', { 'abc' => 123 } ),
  'made hmac get request';

is $get->res->{success}, 'get request working', 'get request response correct';

ok my $post = $wj->post( '/post/request', { a => 'b', x => 'y' } ),
  'made hmac post request';

is $post->res->{success}, 'post request working',
  'post request response correct';

done_testing;
