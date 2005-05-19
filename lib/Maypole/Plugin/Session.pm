package Maypole::Plugin::Session;

use warnings;
use strict;

use Maypole ();
use Maypole::Constants ();
use Maypole::Config ();

use CGI::Simple::Cookie ();

Maypole::Config->mk_accessors('session');
Maypole->mk_accessors( 'session' );


=head1 NAME

Maypole::Plugin::Session - simple sessions for Maypole

=cut

our $VERSION = 0.02;

=head1 SYNOPSIS

    use Maypole::Application qw( Session );
    
    # Elsewhere in your app:
    my $session = $r->session;
    
=head1 DESCRIPTION

L<Maypole::Plugin::Authentication::UserSessionCookie|Maypole::Plugin::Authentication::UserSessionCookie> 
has a cryptic paragraph explaining how to use that module to support basic sessions without users. This 
module saves you from having to figure it out. 

Provides C<session> and C<delete_session> methods for your Maypole request class. 

=head1 PUBLIC METHODS

=over 4

=item session

Returns the session object/hash.

=item delete_session

Deletes the session and cookie.

=cut

# like MP::P::Authentication::UserSessionCookie::logout()
sub delete_session
{
    my ( $r ) = @_;
    
    if ( $r->session ) 
    {
        my $s = tied( %{$r->session} );
        
        $s->delete if ref $s;
    }
    
    $r->_delete_cookie;
}

=back

=head1 PRIVATE METHODS

These are only necessary if you are writing custom C<authenticate> method(s). 
Otherwise, they are called for you.

=over 4

=item authenticate

This is called early in the Maypole request workflow, and is used as the hook to 
call C<get_session>. If you are writing your own C<authenticate> method(s), either in 
model classes or in the request classes, make sure your C<authenticate> method calls 
C<get_session>.
    
=cut

sub authenticate
{
    my ( $r ) = @_;
    
    $r->get_session;
    
    return Maypole::Constants::OK;  
}

=item get_session

Retrieves the cookie from the browser and matches it up with a session in the store. Puts
the session in the C<session> slot of the request. 

You should call this method inside any custom C<authenticate> methods.

=cut

# - combines get_user and login_user from MP::P::Authentication::UserSessionCookie
sub get_session
{
    my ( $r ) = @_;
    
    my %jar = CGI::Simple::Cookie->parse( $r->headers_in->get( 'Cookie' ) );
    
    my $cookie_name = $r->config->{session}->{cookie_name} || "sessionid";
    
    my $sid = $jar{ $cookie_name }->value if exists $jar{ $cookie_name };
    
    warn "SID from cookie: $sid" if $r->debug && defined $sid;
    
    # Clear it, as 0 is a valid sid.
    $sid = undef unless $sid; 
    
    my $session_class = $r->config->session->{class} || 'Apache::Session::File';
    
    $session_class->require || die "Couldn't load session class $session_class";
    
    my $session_args = $r->config->session->{args} || { Directory     => "/tmp/sessions",
                                                        LockDirectory => "/tmp/sessionlock",
                                                        };
    
    my %session = ();
    
    eval { tie %session, $session_class, $sid, $session_args };
    
    if ( $@ ) 
    { 
        die $@ unless $@ =~ /does not exist in the data store/;
        
        warn "Session $sid does not exist in the data store - deleting cookie" if $r->debug;
        
        return $r->_delete_cookie;
    }
    
    $r->_set_cookie( value   => $session{_session_id}, 
                     expires => $r->config->session->{cookie_expiry} || '+3M',
                     );
    
    $r->session( \%session );
}

sub _set_cookie
{
    my ( $r, %cookie ) = @_;
    
    my $cookie_name = $r->config->session->{cookie_name} || "sessionid";
    
    my $cookie = CGI::Simple::Cookie->new(
        -name       => $cookie_name,
        -value      => $cookie{value},
        -expires    => $cookie{expires},
        -path       => URI->new($r->config->uri_base)->path
        );
        
    warn "Baking: ". $cookie->as_string if $r->debug;
    
    $r->headers_out->set( 'Set-Cookie', $cookie->as_string );
}

sub _delete_cookie
{
    my ( $r ) = @_;
    
    $r->_set_cookie( value   => '',
                     expires => '-10m',
                     );
}

=back

=head1 Configuration

The class provides sensible defaults for all that it does, but you can
change its operation through Maypole configuration parameters.

First, the session data. This is retrieved as follows. The Maypole
configuration parameter C<<$config->session->{class}>> is
used as a class to tie the session hash, and this defaults to
C<Apache::Session::File>. The parameters to the tie are the session ID
and the value of the C<<$config->session->{args}>>
configuration parameter. This defaults to:

    { Directory     => "/tmp/sessions", 
      LockDirectory => "/tmp/sessionlock" 
      }

You need to create these directories with appropriate permissions if you
want to use these defaults.

For instance, you might instead want to say:

    $r->config->session({
        class => "Apache::Session::Flex",
        args  => {
            Store     => 'DB_File',
            Lock      => 'Null',
            Generate  => 'MD5',
            Serialize => 'Storable'
         }
    });

The cookie name is retrieved from C<<$config->session->{cookie_name}>>
but defaults to "sessionid". It defaults to expiry after 3 months, and 
this can be set in C<<$config->session->{cookie_expiry}>.

=head1 SEE ALSO

L<Maypole::Plugin::Authentication::UserSessionCookie|Maypole::Plugin::Authentication::UserSessionCookie>, 
from which nearly all of the code was stolen. 

=head1 AUTHOR

David Baird, C<< <cpan@riverside-cms.co.uk> >>

=head1 BUGS

Please report any bugs or feature requests to
C<bug-maypole-plugin-session@rt.cpan.org>, or through the web interface at
L<http://rt.cpan.org/NoAuth/ReportBug.html?Queue=Maypole-Plugin-Session>.
I will be notified, and then you'll automatically be notified of progress on
your bug as I make changes.

=head1 COPYRIGHT & LICENSE

Copyright 2005 David Baird, All Rights Reserved.

This program is free software; you can redistribute it and/or modify it
under the same terms as Perl itself.

=cut

1; # End of Maypole::Plugin::Session
