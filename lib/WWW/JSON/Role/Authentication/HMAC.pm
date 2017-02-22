package WWW::JSON::Role::Authentication::HMAC;

use Moo::Role;
use Safe::Isa;
use DateTime;
use MIME::Base64 qw( decode_base64 encode_base64 );
use Digest::SHA qw(sha256);
use Digest::HMAC qw(hmac);

requires 'authentication';
requires 'ua';

sub _validate_HMAC {
    my ( $self, $auth ) = @_;

    for ( qw/ api_key_id api_secret /) {
        die "Required parameter $_ missing for " . __PACKAGE__ . " authentication"
          unless exists( $auth->{$_} );
    }
}

sub _canonical_request {
    my ( $self, $req, $date ) = @_;
    my @parts = ( $req->method, $req->uri, $date );
    push @parts, $req->header('Content_Type') if $req->method eq 'POST';
    push @parts, $req->content if $req->method eq 'POST';
    return join '' => @parts;
}

sub _auth_HMAC {
    my ( $self, $auth, $req ) = @_;

    my $date = DateTime->now->strftime('%Y-%m-%dT%H:%M:%SZ');
    my $canonical_request = $self->_canonical_request($req, $date);
    my $secret = decode_base64( $auth->{api_secret} );
    my $signature = encode_base64 hmac( $canonical_request, $secret, \&sha256 );
    chomp $signature;

    my $authorization = sprintf 'HHMAC; key=%s; signature=%s; date=%s',
      $auth->{api_key_id}, $signature, $date;
    $req->header( Authorization => $authorization );
}

1;
