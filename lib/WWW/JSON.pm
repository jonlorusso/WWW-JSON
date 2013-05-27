package WWW::JSON;
use 5.008005;
use strict;
use warnings;

our $VERSION = "0.01";
use LWP::UserAgent;
use Moo;
use Try::Tiny;
use URI;
use WWW::JSON::Response;
use Data::Dumper::Concise;
use Safe::Isa;
use JSON::XS;

has ua => (
    is      => 'lazy',
    handles => [qw/timeout/],
    default => sub { LWP::UserAgent->new }
);
has base_url => (
    is     => 'rw',
    coerce => sub {
        my $base_url = shift;
        return $base_url if ( $base_url->$_isa('URI') );
        if ( ref($base_url) eq 'ARRAY' ) {
            my ( $url, $params ) = @{$base_url};
            my $u = URI->new($url);
            $u->query_form(%$params);
            return $u;
        }
        return URI->new($base_url);
    }
);
has body_params => ( is => 'rw', default => sub { +{} } );
has post_body_format => (
    is      => 'rw',
    default => sub { 'serialized' },
    clearer => 1,
    isa     => sub {
        die "Invalid post_body_format $_[0]"
          unless ( $_[0] eq 'serialized' || $_[0] eq 'JSON' );
    }
);
has json => ( is => 'ro', default => sub { JSON::XS->new } );


has default_response_transform => ( is => 'rw', clearer => 1 );
with 'WWW::JSON::Role::Authorization';
sub get    { shift->req( 'GET',    @_ ) }
sub post   { shift->req( 'POST',   @_ ) }
sub put    { shift->req( 'PUT',    @_ ) }
sub delete { shift->req( 'DELETE', @_ ) }
sub head   { shift->req( 'HEAD',   @_ ) }


sub req {
    my ( $self, $method, $path, $params ) = @_;
    unless ( $path->$_isa('URI') ) {
        $path =~ s|^/|./|;
        $path = URI->new($path);
    }
    my $p =
      ( $method eq 'GET' )
      ? $params
      : { %{ $self->body_params }, %{ $params // {} } };
    my $abs_uri =
      ( $path->scheme ) ? $path : URI->new_abs( $path, $self->base_url );
    $abs_uri->query_form( $path->query_form, $self->base_url->query_form );

    return $self->_make_request( $method, $abs_uri, $p );
}

sub body_param {
    my ( $self, $k, $v ) = @_;
    $self->body_param->{$k} = $v;
}

sub _create_post_body {
    my ( $self, $p ) = @_;
    if ( $self->post_body_format eq 'JSON' ) {
        return (
            'Content-Type' => 'application/json',
            Content        => $self->json->encode($p)
        );
    }
    return ( Content => $p );
}

sub _make_request {
    my ( $self, $method, $uri, $p ) = @_;

    my $lwp_method = lc($method);
    die "Method $method not implemented" unless ( $self->ua->can($lwp_method) );
    my %payload;

    if ($p) {
        if ( $method eq 'GET' ) {
            $uri->query_form( $uri->query_form, %$p );
        }
        else { %payload = $self->_create_post_body($p) }
    }
    my $resp = $self->ua->$lwp_method( $uri->as_string, %payload );

    return WWW::JSON::Response->new(
        {
            http_response      => $resp,
            response_transform => $self->default_response_transform
        }
    );
}

1;
__END__

=encoding utf-8

=head1 NAME

WWW::JSON - Make working with JSON Web API's as painless as possible

=head1 SYNOPSIS

    use WWW::JSON;
    
    my $wj = WWW::JSON->new(
        base_url    => 'https://graph.facebook.com',
        body_params => { access_token => 'XXXXX' }
    );
    my $r = $wj->get('/me', { fields => 'email' } );
    my $email = $r->res->{email} if ($r->success);

=head1 DESCRIPTION

WWW::JSON is an easy interface to any modern web API that returns JSON.

It tries to make working with these API's as intuitive as possible.

=head1 WHY SHOULD I CARE?

When using abstracted web API libraries I often ran into issues where bugs in the library interfere with proper api interactions, or features  are added to the API that the library doesn't support.

In these cases the additional abstraction winds up making life more difficult.

Abstracted libraries do offer benefits.

    -Auth is taken care of for you.
    -Cuts out boilerplate
    -Don't have to think about HTTP status, JSON, or parameter serialization

I wanted just enough abstraction to get the above benefits, but no more.

Thus, WWW::JSON was born. Perl + Web + JSON - tears

=head1 WHAT YOU GET

-Light on dependencies

-Don't repeat yourself

    -Set a url that all requests will be relative to
    -Set query params included on all requests
    -Set body params included on all requests that contain a POST body
    -Transform the response of all API requests. Useful if an API returns data in a silly structure.

-Work with APIs that require different parameter serialization

    - Serialized post bodys (Facebook, Foursquare)
    - JSON-ified post bodys (Github, Google+)

-Authentication

    -Basic
    -OAuth 1.0a
    -OAuth2

-Avoids boilerplate

    -Don't have to worry about going from JSON => perl and back
    -Handles HTTP and JSON decode errors gracefully



=head1 PARAMETERS

=head2 base_url

The root url that all requests will be relative to.

Any query parameters included in the base_url will be added to every request made to the api

Alternatively, an array ref consisting of the base_url and a hashref of query parameters can be passed like so:

base_url => [ 'http://google.com', { key1 => 'val1', key2 => 'val2'} ]

=head2 body_params

Parameters that will be added to every non-GET request made by WWW::JSON.

=head2 default_response_transform

Many API's have a lot of boilerplate around their json responses.

For example lets say every request's meaningful payload is included inside the first array index of a hash key called 'data'.

Instead of having to do $res->{data}->[0]->{key1}, you can specify default_response_transform as sub { shift->{data}->[0] } 

Then in your responses you can get at key1 directly by just doing $res->{key1}

NOTE: This transform only occurs if no HTTP errors or decoding errors occurred. If we get back an HTTP error status it seems more useful to get back the entire decoded JSON blob


=head2 authorization_basic

Accepts a hashref of basic HTTP auth credentials in the format { username => 'antipasta', password => 'hunter2' }

Every request made by WWW::JSON will use these credentials.

=head2 authorization_oauth1

Accepts a hashref of OAuth 1.0A credentials. All requests made by WWW::JSON will use these credentias.


=head1 METHODS

=head2 get

$wj->get($path,$params)

Performs a GET request to the relative path $path. $params is a hashref of url query parameters.

=head2 post

$wj->post($path,$params)

Performs a POST request. $params is a hashref of parameters to be passed to the post body

=head2 put

$wj->put($path,$params)

Performs a PUT request. $params is a hashref of parameters to be passed to the post body

=head2 req

$wj->req($method,$path,$params)

Performs an HTTP request of type $method. $params is a hashref of parameters to be passed to the post body

=head2 body_param

Add/Update a single body param


=head1 LICENSE

Copyright (C) Joe Papperello.

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 AUTHOR

Joe Papperello E<lt>antipasta@cpan.orgE<gt>

=head1 SEE ALSO

-App::Adenosine - Using this on the command line definitely served as some inspiration for WWW::JSON.

-Net::HTTP::Spore - I found this while researching other modules in this space. It's still a bit abstracted from the actual web request for my taste, but it's obvious the author created it out of some of the same above frustrations and it looks useful.



=cut

