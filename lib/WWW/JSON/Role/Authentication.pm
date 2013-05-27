package WWW::JSON::Role::Authentication;
use Moo::Role;
use Data::Dumper::Concise;
has authentication => (
    is      => 'rw',
    clearer => 1,
    default => sub { +{} },
    isa     => sub {
        return if ref( $_[0] ) eq 'CODE';
        die "Only 1 authentication method can be supplied "
          unless keys( %{ $_[0] } ) <= 1;
    },
    trigger => 1,

);

sub _trigger_authentication {
    my ( $self, $auth ) = @_;
    return unless ($auth);
    return if ref($auth) eq 'CODE';

    my ( $name, $data ) = %$auth;
    my $role = __PACKAGE__ . '::' . $name;

    warn "APPLYING[$role] " . Dumper($data);

    Moo::Role->apply_roles_to_object( $self, $role )
      unless $self->does($role);

    my $handler   = '_auth_' . $name;
    my $validator = '_validate_' . $name;

    die "No handler found for auth type [$name]"
      unless ( $self->can($handler) );
    $self->$validator($data) if ( $self->can($validator) );
}

before clear_authentication => sub {
    my $self = shift;
    $self->ua->default_headers->remove_header('Authorization')
      if ( $self->authentication );
};

around _make_request => sub {
    my ( $orig, $self ) = ( shift, shift );
    if ( ref( $self->authentication ) eq 'CODE' ) {
        $self->authentication->( $self, @_ );
    }
    elsif ( my ( $auth_type, $auth ) = %{ $self->authentication } ) {
        my $handler   = '_auth_' . $auth_type;
        $self->$handler( $auth, @_ );
    }
    return $self->$orig(@_);
};

after _make_request => sub {
    my $self = shift;
    $self->ua->default_headers->remove_header('Authorization')
      if ( $self->authentication );
};

with qw/WWW::JSON::Role::Authentication::Basic
  WWW::JSON::Role::Authentication::OAuth1
  WWW::JSON::Role::Authentication::OAuth2/;
1;
