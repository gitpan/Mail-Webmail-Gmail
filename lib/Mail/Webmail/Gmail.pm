package Mail::Webmail::Gmail;

use lib qw(lib);
use strict;

require LWP::UserAgent;
require HTTP::Headers;
require HTTP::Cookies;
require Crypt::SSLeay;
require Exporter;

$VERSION = "0.02";

our @ISA = qw(Exporter);
our @EXPORT_OK = ();
our @EXPORT = ();

our $USER_AGENT = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.4b) Gecko/20030430 Mozilla Firebird/0.6"; 
our $MAIL_URL = "http://gmail.google.com/gmail";
our $LOGIN_URL = "https://www.google.com/accounts/ServiceLoginBoxAuth";
our $VERIFY_URL = "https://www.google.com/accounts/CheckCookie?service=mail&chtml=LoginDoneHtml";

our %FOLDERS = (
	'INBOX'   => '^I',
	'STARRED' => '^T',
	'SPAM'    => '^S',
	'TRASH'   => '^K',
);

$| = 1;

sub new {
	my $class = shift;
	my %args = @_;

	my $ua = new LWP::UserAgent( agent => $USER_AGENT );
	
	my $self = bless {
		_username      => $args{username}      || die('No username defined'),
		_password      => $args{password}      || die('No password defined'),
		_login_url     => $args{login_server}  || $LOGIN_URL,
		_verify_url    => $args{verify_server} || $VERIFY_URL,
		_mail_url      => $args{mail_server}   || $MAIL_URL,
		_proxy_user    => $args{proxy_username}|| '',
		_proxy_pass    => $args{proxy_password}|| '',
		_proxy_name    => $args{proxy_name}    || '',
		_proxy_enable  => 0                    || ( defined( $args{proxy_username} ) && defined( $args{proxy_password} ) && defined( $args{proxy_name} ) ),
		_logged_in     => 0,
                _err_str       => '',
		_gv            => '',
		_sid           => '',
		_version       => '', ### gmail version
		_ua            => $ua,
		_debug_level   => 0,
		_error          => 0,
	}, $class;

	return $self;
}

sub error {
	my ( $self ) = @_;
	return( $self->{_error} );
}

sub error_msg {
	my ( $self ) = @_;
	return( $self->{_err_str} );
}

sub login {
	#re-login on each individual run.  Add save to disk?

	my ( $self ) = @_;

	return 0 if $self->{_logged_in};

	my $req = HTTP::Request->new( POST => $self->{_login_url} );
	my ( $cookie );

	if ( $self->{_proxy_enable} ) {
		$ENV{HTTPS_PROXY} = $self->{_proxy_name};
		$ENV{HTTPS_PROXY_USERNAME} = $self->{_proxy_user};
		$ENV{HTTPS_PROXY_PASSWORD} = $self->{_proxy_pass};
	}

	$req->content_type( "application/x-www-form-urlencoded" );
	$req->content( 'service=mail&Email=' . $self->{_username} . '&Passwd=' . $self->{_password} . '&null=Sign%20in' );
	my $res = $self->{_ua}->request( $req );

	if ( $res->is_success() ) {
		my $header = $res->header( 'Set-Cookie' );
		$header =~ /(SID=.*?;)/;
		$cookie = $1;
		$cookie =~ /^SID=(.*);/;
		$self->{_sid} = $1;
		$res->content() =~ /cookieVal=[ ]?\"(.*)\";/;
		$cookie .= "GV=$1";
		$self->{_gv} = $1;
		$self->{_cookie} = HTTP::Headers->new( Cookie => $cookie );
		$req = HTTP::Request->new( GET => $self->{_verify_url}, $self->{_cookie} );
		$res = $self->{_ua}->request( $req );
		if ( $res->is_success() ) {
			if ( $res->content() =~ /My Account/ ) {
				$self->{_logged_in} = 1;
				if ( $self->{_proxy_enable} ) {
					$self->{_ua}->proxy( 'http', $self->{_proxy_name} );
				}
				set_version( $self );
				return( 1 );
			} else {
				$self->{_error} = 1;
				$self->{_err_str} .= "Error: Could not login with those credentials\n";
				return undef;
			}
		} else {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: While requesting: '$res->{_request}->{_uri}'.\n";
			$self->{_err_str} .= "  Additionally, HTTP error: " . $res->status_line . "\n";
			return undef;
		}
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: While requesting: '$res->{_request}->{_uri}'.\n";
		$self->{_err_str} .= "  Additionally, LWP returned error: " . $res->status_line . "\n";
		return undef;
	}
}

sub check_login {
	my ( $self ) = @_;

	if ( !$self->{_logged_in} ) {
		unless ( $self->login() ) {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: Could not Login.\n";
			return undef;
		}
	}
	return ( $self->{_logged_in} );
}

sub set_version {
	# sample version info line - D(["v", "fc00000000000000"]);
	my ( $self ) = @_;

	my $res = get_page( $self );

	my %functions = %{ parse_page( $self, $res ) };
	if ( $self->{_error} ) {
		return( undef );
	}

	if ( $res->is_success() ) {
		if ( defined( $functions{ 'v' } ) ) {
			$self->{_version} = $functions{ 'v' };
			return( 1 );
		} else {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: Could not find version info.\n";
			return( undef );
		}
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: While requesting: '$res->{_request}->{_uri}'.\n";
		return( undef );
	}
}

sub get_page {
	# input: either send search and the folder name( inbox, all, starred, etc ) or send label => 'labelname'
	# output: returns LWP $res

	my ( $self ) = shift;
	my ( %args ) = (
		search  => 'all',
		view    => 'tl',
		start   => 0,
		method  => '',
		@_, );
	my ( $res, $req );

	if ( defined( $args{ 'label' } ) ) {
		$args{ 'label' } = validate_label( $self, $args{ 'label' } );
		if ( $self->error ) {
			return( undef );
		} else {
			$args{ 'cat' } = $args{ 'label' };
			delete( $args{ 'label' } );
			$args{ 'search' } = 'cat';
		}
	}

	unless ( check_login( $self ) ) { return( undef ) };

	my ( $url, $method, $view );

	$method = $args{ 'method' };
	delete( $args{ 'method' } );
	if ( $method eq 'post' ) {
		$view = $args{ 'view' };
		delete( $args{ 'view' } );
	}

	map{ if ( defined( $args{ $_ } ) && ( $args{ $_ } ne '' ) ) { $url .= "$_=$args{$_}&"; } } %args;
	chop( $url );

	if ( $method eq 'post' ) {
		$req = HTTP::Request->new( POST => $self->{_mail_url} . "?view=$view", $self->{_cookie} );
		if ( $self->{_proxy_enable} ) {
			$req->proxy_authorization_basic( $self->{_proxy_user}, $self->{_proxy_pass} );
		}
		$req->content_type( "application/x-www-form-urlencoded" );
		$req->content( $url );
		$res = $self->{_ua}->request( $req );
	} else {
		delete( $args{ 'method' } );
		$req = HTTP::Request->new( GET => $self->{_mail_url} . "?$url", $self->{_cookie} );
		if ( $self->{_proxy_enable} ) {
			$req->proxy_authorization_basic( $self->{_proxy_user}, $self->{_proxy_pass} );
		}
		$res = $self->{_ua}->request( $req );
	}

	if ( $res->is_success() ) {
		my ( $cookie );
		$res->header( 'Set-Cookie' ) =~ /SID=(.*?);/;
		$self->{_sid} = $1;
		$cookie = "SID=$1;";
		$res->header( 'Set-Cookie' ) =~ /GMAIL_AT=(.*?);/;
		$cookie .= "GMAIL_AT=$1;";
		$self->{_gmail_at} = $1;
		$cookie .= "GV=" . $self->{_gv} . ';';
		$self->{_cookie} = HTTP::Headers->new( Cookie => $cookie );
	}

	return ( $res );
}

sub size_usage {
	# Size usage is marked by the line - 'D(["qu","0 MB","1000 MB"]);'

	my ( $self, $res ) = @_;


	unless ( check_login( $self ) ) { return( undef ) };

	unless ( $res ) {
		$res = get_page( $self );
	}

	my %functions = %{ parse_page( $self, $res ) };

	if ( $self->{_error} ) {
		return( undef );
	}

	if ( $res->is_success() ) {
		if ( defined( $functions{ 'qu' } ) ) {
			$functions{ 'qu' }[0] =~ /(.*)\s/;
			my $used = $1;
			$functions{ 'qu' }[1] =~ /(.*)\s/;
			my $size = $1;
			return( $size - $used );
		} else {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: Could not find free space info.\n";
			return( undef );
		}
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: While requesting: '$res->{_request}->{_uri}'.\n";
		return( undef );
	}
}

sub get_labels {
	# Labels are marked by the line - 'D(["ct",[(.*)]]);'

	my ( $self, $res ) = @_;

	unless ( check_login( $self ) ) { return( undef ) };

	unless ( $res ) {
		$res = get_page( $self, search => 'inbox' );
	}

	if ( $res->is_success() ) {
		my %functions = %{ parse_page( $self, $res ) };
		# Labels are returned as an array in the format [ ['Name', 'Value'] ]
		# Not sure what the value corrisponds to, as its always been 0 for me.

		if ( $self->{_error} ) {
			return( undef );
		}

		unless ( defined( $functions{ 'ct' } ) ) {
			return( undef );
		}

		my @fields = @{ extract_fields( $functions{ 'ct' }->[0] ) };
		foreach ( @fields ) {
			$_ = ${ extract_fields( $_ ) }[0];
			$_ = remove_quotes( $_ );
		}
		if ( @fields ) {
			return( @fields );
		} else {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: No Labels found.\n";
			return( undef );
		}
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: While requesting: '$res->{_request}->{_uri}'.\n";
		return( undef );
	}	
}

sub validate_label {
	# uses the same guidleines as google does when creating a new label.
	# label creation is not implemented yet.

	my ( $self, $label ) = @_;

	if ( defined( $label ) ) {
		$label =~ s/^\s//;
		$label =~ s/\s$//;
		if ( $label =~ /\^/ ) {
			my $is_folder = 0;
			foreach ( keys %FOLDERS ) {
				if ( $FOLDERS{ $_ } eq uc( $label ) ) {
					$is_folder = 1;
				}
			}
			unless ( $is_folder ) {
				$self->{_error} = 1;
				$self->{_err_str} .= "Error: Labels cannot contain the character '^'.\n";
				return( undef );
			}
		}
		if ( length( $label ) > 40 ) {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: Labels cannot contain more than 40 characters.\n";
			return( undef );
		}
		if ( length( $label ) == 0 ) {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: No labels specified.\n";
			return( undef );
		}
		return( $label );
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: No labels specified.\n";
		return( undef );
	}
}

sub get_messages {
	my ( $self ) = shift;
	my ( %args ) = (
		@_, );
	my ( $res, $req );

	if ( defined( $args{ 'label' } ) ) {
		$args{ 'label' } = validate_label( $self, $args{ 'label' } );
		if ( $self->error ) {
			return( undef );
		} else {
			$args{ 'cat' } = $args{ 'label' };
			delete( $args{ 'label' } );
			$args{ 'search' } = 'cat';
		}
	}

	unless ( check_login( $self ) ) { return( undef ) };

	$res = get_page( $self, %args );

	if ( $res->is_success() ) {
		my %functions = %{ parse_page( $self, $res ) };
		# Messages are returned as an array in the format 
		# [ ['msgid', new, value, 'date received', 'sender email + name', 'value', 'subject', 'blurb', ['labels'], 'attachments', 'msg id again? (might be thread id)', value ] ]
		# Values are the unknowns.

		if ( $self->{_error} ) {
			return( undef );
		}
		my ( @emails, @letters );

		unless ( defined( $functions{ 't' } ) ) {
			return( undef );
		}

		foreach ( @{ $functions{ 't' } } ) {
			my @email_line = @{ extract_fields( $_ ) };
			my %indv_email;
			$indv_email{ 'id' }            = remove_quotes( $email_line[0] );
			$indv_email{ 'new' }           = remove_quotes( $email_line[1] );
			$indv_email{ 'date_received' } = remove_quotes( $email_line[3] );
			$indv_email{ 'sender_email' }  = remove_quotes( $email_line[4] );
				$indv_email{ 'sender_email' } =~ /'\\>(.*?)\\/;
			$indv_email{ 'sender_name' }   = remove_quotes( $1 );
				$indv_email{ 'sender_email' } =~ /_user_(.*?)\\/;
				$indv_email{ 'sender_email' } = remove_quotes( $1 );
			$indv_email{ 'subject' }       = remove_quotes( $email_line[6] );
			$indv_email{ 'blurb' }         = remove_quotes( $email_line[7] );
			$indv_email{ 'labels' } = [ map{ remove_quotes( $_ ) }@{ extract_fields( $email_line[8] ) } ];
				$email_line[9] = remove_quotes( $email_line[9] );
			$indv_email{ 'attachments' } = extract_fields( $email_line[9] ) if ( $email_line[9] ne '' );
			push ( @emails, \%indv_email );
		}
		return ( \@emails );
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: While requesting: '$res->{_request}->{_uri}'.\n";
		return( undef );
	}
}

sub get_indv_email {
	# Email is marked by the lines -  message info: D(["mi"...]); and message body: D("mb"...]);
	my ( $self ) = shift;
	my ( %args ) = (
		view   => 'pt',
		@_, );

	if ( defined( $args{ 'id' } ) && defined( $args{ 'label' } ) ) {
		$args{ 'label' } = validate_label( $self, $args{ 'label' } );
		if ( $self->error() ) {
			return( undef );
		} else {
			$args{ 'cat' } = $args{ 'label' };
			delete( $args{ 'label' } );
			$args{ 'search' } = 'cat';
		}
		$args{ 'th' } = $args{ 'id' };
		delete( $args{ 'id' } );
	} elsif ( defined( $args{ 'msg' } ) ) {
		if ( defined( $args{ 'msg' }->{ 'id' } ) ) {
			$args{ 'th' } = $args{ 'msg' }->{ 'id' };
		} else {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: Not a valid msg reference.\n";
			return( undef );
		}

		if ( defined( @{ $args{ 'msg' }->{ 'labels' } } ) ) {
			if ( $args{ 'msg' }->{ 'labels' }->[0] ne '' ) {
				$args{ 'label' } = validate_label( $self, $args{ 'msg' }->{ 'labels' }->[0] );
				delete( $args{ 'msg' }->{ 'label' } );
				if ( $self->error ) {
					return( undef );
				} else {
					if ( $args{ 'label' } =~ /^\^.$/ ) {
						$args{ 'label' } = cat_to_search( $args{ 'label' } );
						$args{ 'search' } = $args{ 'label' };
					} else {
						$args{ 'cat' } = $args{ 'label' };
						$args{ 'search' } = 'cat';
					}
					delete( $args{ 'label' } );
				}
			}
		}
		delete( $args{ 'msg' } );
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: Must specifie either id and label or send a reference to a valid message with msg.\n";
		return( undef );
	}

	unless ( check_login( $self ) ) { return( undef ) };

	my $res = get_page( $self, %args );

	if ( $res->is_success() ) {
		my %functions = %{ parse_page( $self, $res ) };
		# Messages are returned as an array in the format
		# message info:
		# [ [value, order in thread?, "id", value, value, "sender name", "sender email", "sender name", 'date sent?', 'recpients email', "value", "value", "value", "date read?", "subject", "blurb?", [["attach id", "attachment name", "encoding", value]], value, "value"]
		# Values are the unknowns.

		if ( defined( $functions{ 'mi' } ) ) {
			my %messages;
			my @thread;
			foreach ( @{ $functions{ 'mi' } } ) {
				my %message;
				my @email = @{ extract_fields( $_ ) };
				$email[2] = remove_quotes( $email[2] );
				if ( $email[16] ne '' ) {
					my @attachments = @{ extract_fields( $email[16] ) };
					my @files;
					foreach ( @attachments ) {
						my @attachment = @{ extract_fields( $_ ) };
						my %indv_attachment;
						$indv_attachment{ 'id' }       = remove_quotes( $attachment[0] );
						$indv_attachment{ 'name' }     = remove_quotes( $attachment[1] );
						$indv_attachment{ 'encoding' } = remove_quotes( $attachment[2] );
						$indv_attachment{ 'th' }       = $email[2];
						push( @files, \%indv_attachment );
					}
					$message{ 'attachments' } = \@files;
				}
				$message{ 'id' }      = $email[2];
				$message{ 'sender' }  = remove_quotes( $email[6] );
				$message{ 'sent' }    = remove_quotes( $email[8] );
				$message{ 'to' }      = remove_quotes( $email[9] );
				$message{ 'read' }    = remove_quotes( $email[13] );
				$message{ 'subject' } = remove_quotes( $email[14] );
				if ( $args{ 'th' } eq $email[2] ) {
					my $body = extract_fields( $functions{ 'mb' }->[0] );
					$message{ 'body' } = $body->[0];
				}
				$messages{ $email[2] } = \%message;
			}
			return ( \%messages );
		}

	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: While requesting: '$res->{_request}->{_uri}'.\n";
		return( undef );
	}
}

sub get_attachment {
	# input: expects caller to send attid ( the attachment ID ) and msgid ( the message ID )
	# returns: a reference to the attachment
	my ( $self ) = shift;
	my ( %args ) = (
		view   => 'att',
		disp   => 'attd',
		search => '',
		@_, );

	if ( defined( $args{ 'attid' } ) && defined( $args{ 'msgid' } ) ) {
		$args{ 'th' } = $args{ 'msgid' };
		delete( $args{ 'msgid' } );
	} elsif ( defined( $args{ 'attachment' } ) ) {
		if ( defined( $args{ 'attachment' }->{ 'id' } ) ) {
			$args{ 'attid' } = $args{ 'attachment' }->{ 'id' };
		} else {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: Not a valid attachment.1\n";
			return( undef );
		}
		if ( defined( $args{ 'attachment' }->{ 'th' } ) ) {
			$args{ 'th' } = $args{ 'attachment' }->{ 'th' };
		} else {
			$self->{_error} = 1;
			$self->{_err_str} .= "Error: Not a valid attachment.2\n";
			return( undef );
		}

		delete( $args{ 'attachment' } );		
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: Must supply attid and msgid or a reference to an attachment through 'attachment'.\n";
		return( undef );
	}

	
	unless ( check_login( $self ) ) { return( undef ) };
	
	my $res = get_page( $self, %args );

	if ( $res->is_success() ) {
		my $attachment = $res->content();
		return( \$attachment );
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: While requesting attachment: '$res->{_request}->{_uri}'.\n";
		return( undef );
	}
}

sub recurse_slash {
	my ( $field ) = @_;
	my $count_slashes = 0;
	my $end_slash = 0;
	my $cnt = length( $field );

	while ( ( $cnt > 0 ) && ( !$end_slash ) ){
		$cnt--;
		my $char = substr( $field, $cnt, 1 );
		if ( $char eq '\\' ) {
			if ( $count_slashes ) {
				$count_slashes = 0;
			} else {
				$count_slashes = 1;
			}
		} else {
			$end_slash = 1;
		}
	}

	return( $count_slashes );
}

sub extract_fields {
	# I would really like to find a module to do this, but Text::CSV fails on ,[data, data],
	# and Text::Balanced gets confused unless the delim is the same throughout the string.
	# input: string (line to be parsed)
	# output: array (elements)

	my ( $line ) = @_;
	my @fields;
	my $in_quotes = 0;
	my $in_brackets = 0;
	my $delim_count = 0;
	my $end_field = 0;
	my $field = '';
	my $char;

	my $cnt;
	for ( $cnt=0; $cnt < length( $line ); $cnt++ ) {
		$char = substr( $line, $cnt, 1 );
		if ( $in_quotes ) {
			if ( ( $char eq '"' ) && ( !recurse_slash( $field ) ) ) {
				$in_quotes = 0;
				$end_field = 1;
			}
			$field .= $char;
		} elsif ( $in_brackets ) {
			if ( $char eq '[' ) {
				$delim_count++;
				$field .= $char;
			} elsif ( $char eq ']' ) {
				$delim_count--;
				if ( $delim_count == 0 ) {
					$in_brackets = 0;
					$end_field = 1;
					if ( $field eq '' ) {
						push( @fields, '' );
					}
				} else {
					$field .= $char;
				}
			} else {
				$field .= $char;
			}
		} elsif ( $char eq '"' ) {
			$in_quotes = 1;
			$field .= $char;
		} elsif ( $char eq '[' ) {
			$in_brackets = 1;
			$delim_count = 1;
		} elsif ( $char ne ',' ) {
			$field .= $char;
		} elsif ( $char eq ',' ) {
			$end_field = 1;
		}

		if ( $end_field ) {
			if ( $field ne '' ) {
				push ( @fields, $field );
			}			$field = '';
			$end_field = 0;
		}
	}

	if ( $field ne '' ) {
		push ( @fields, $field );
	}
	return( \@fields );
}

sub remove_quotes {
	my ( $field ) = @_;

	if ( defined( $field ) ) {
		$field =~ s/^"(.*)"$/$1/;
	}

	return ( $field );
}

sub cat_to_search {
	my ( $cat ) = @_;

	my %REVERSE_CAT = map{ $FOLDERS{ $_ } => $_ }(keys %FOLDERS);

	if ( defined( $REVERSE_CAT{ uc( $cat ) } ) ) {
		return( lc( $REVERSE_CAT{ uc( $cat ) } ) );
	} else {
		return( $cat );
	}
}

sub parse_page {
	my ( $self, $res ) = @_;

	if ( $res->is_success() ) {
		my $page;
		$res->content() =~ /<!--(.*)\/\/-->/s;
		$page = $1;
		my ( %functions );
		while ( $page =~ /D\((.*?)\);\n/mgs ) {
			my $line = $1;
			$line =~ s/\n//g;
			$line =~ s/^\["(.*?)",?//;
			my $function = $1;
			$line =~ s/\]$//;
			if ( ( uc( $function ) eq 'MI' ) || ( uc( $function ) eq 'MB' ) ) {
				$functions{ $function } .= "[$line],";
			} else {
				$functions{ $function } .= "$line,";
			}
		}
		foreach ( keys %functions ) {
			chop( $functions{ $_ } );
			my $fields = extract_fields( $functions{ $_ } );
			$functions{ $_ } = $fields;
		}
		return ( \%functions );
	} else {
		$self->{_error} = 1;
		$self->{_err_str} .= "Error: While requesting: '$res->{_request}->{_uri}'.\n";
		return( undef );
	}
}

1;

__END__

=head1 NAME

GMAIL - Interface to Google webmail

=head1 SYNOPSIS

	# Perl script that logs in to Gmail, retrieves the user defined labels
	# Then prints out all new messages under the first label

	use gmail;

	my $gmail = gmail->new( 
				username => 'username', password => 'password',
			);

	my @labels = $gmail->get_labels();

	my $messages = $gmail->get_messages( label => $labels[0] );

	foreach ( @{ $messages } ) {
		if ( $_->{ 'new' } ) {
			print "Subject: " . $_->{ 'subject' } . " / Blurb: " . $_->{ 'blurb' } . "\n";
		}
	}

=head1 ABSTRACT

This perl module uses objects to make it easy to interface with Gmail.  I eventually hope to
implement all of the functionality of the Gmail website, plus additional features.

=head1 DESCRIPTION

Because Gmail is currently in Beta testing, expect this module to break as they make updates
to thier interface.  I will attempt to keep this module in line with the changes they make, but,
if after updating to the newest version of this module, the feature that you require still doesn't
work, please contact me with the issue.

=head2 STARTING A NEW GMAIL SESSION

The standard call for starting a new gmail session is simply

	my $gmail = gmail->new(	username => 'username', password => 'password',	);

This module does support the use of a proxy server

	my $gmail = gmail->new(	username => 'username', password => 'password',	
				proxy_username => 'proxy_username',
				proxy_password => 'proxy_password',
				proxy_name => 'proxy_server' );

After that, you are free to start making requests for data.

=head2 RETRIEVING LABELS

Returns an array of all user defined labels.

	my @labels = $gmail->get_labels();

=head2 RETRIEVING MESSAGE LISTS

By default, get_messages returns a reference to an AoH with the messages from the 'all'
folder.  To change this behavior you can either send a label

	my $messages = $gmail->get_messages( label => 'work' );

Or request a gmail provided folder using one of the provided variables

	'INBOX'
	'STARRED'
	'SPAM'
	'TRASH'

	Ex.

	my $messages = $gmail->get_messages( label => $Gmail::FOLDERS{ 'INBOX' } );

The Array of hashes is in the following format

	$indv_email{ 'id' }
	$indv_email{ 'new' }
	$indv_email{ 'date' }
	$indv_email{ 'sender' }
	$indv_email{ 'subject' }
	$indv_email{ 'blurb' }
	$indv_email{ 'labels' } = Array
	$indv_email{ 'attachments' } = Array

The format provided by Gmail is ( unknowns are denoted by value )

	[ ['msgid', is new?, value, 'date', 'sender email + name', 'value', 'subject', 'blurb', ['labels'], 
	'attachments', 'msg id again? (might be thread id)', value ] ]

=head2 SPACE REMAINING

Returns a scalar with the amount of MB remaining in you account.

	my $remaining = $gmail->size_usage();

=head2 INDIVIDUAL MESSAGES

There are two ways to get an individual message:

	By sending a reference to a specific message returned by get_messages

	#prints out the message body for all messages in the starred folder
	my $messages = $gmail->get_messages( label => $Gmail::FOLDERS{ 'STARRED' } );
	foreach ( @{ $messages } ) {
		my $message = $gmail->get_indv_email( msg => $_ );
		print "$message->{ $_->{ 'id' } }->{ 'body' }\n";
	}

	Or by sending a message ID and Label that the message resides in

	#retrieve specific email message for review
	my $msgid = 'F000000000';
	my $message = $gmail->get_indv_email( id => $msgid, label => 'label01' );
	print "$message->{ $msgid }->{ 'body' }\n";

returns a Hash of Hashes containing the data from an individual message in the following format:

Hash of messages in thread by ID
	$indv_email{ 'id' }
	$indv_email{ 'sender' }
	$indv_email{ 'sent' }
	$indv_email{ 'to' }
	$indv_email{ 'read' }
	$indv_email{ 'subject' }
	$indv_email{ 'attachments' } = Array of Arrays
	$indv_email{ 'body' } (if it is the main message in the thread)

The format provided by Gmail is ( unknowns are denoted by value )

	[ [value, order in thread?, "id", value, value, "sender name", "sender email", "sender name", 'date sent?', 
	'recpients email', "value", "value", "value", "date read?", "subject", "blurb?", [["attach id", 
	"attachment name", "encoding", value]], value, "value"]

=head2 ATTACHMENTS

There are two ways to get an attachment:

	By sending a reference to a specific attachment returned by get_indv_email

	#creates an array of references to every attachment in your account
	my $messages = $gmail->get_messages();
	my @attachments;

	foreach ( @{ $messages } ) {
		my $email = $gmail->get_indv_email( msg => $_ );
		if ( defined( $email->{ $_->{ 'id' } }->{ 'attachments' } ) ) {
			foreach ( @{ $email->{ $_->{ 'id' } }->{ 'attachments' } } ) {
				push( @attachments, $gmail->get_attachment( attachment => $_ ) );
				if ( $gmail->error() ) {
					print $gmail->error_msg();
				}
			}
		}
	}

	Or by sending the attachment ID and message ID

	#retrieve specific attachment
	my $msgid = 'F000000000';
	my $attachid = '0.1';
	my $attach_ref = $gmail->get_attachment( attid => $attachid, msgid => $msgid );

Returns a reference to a scalar that holds the data from the attachment.

=head1 SAMPLE GMAIL OUTPUT

This is included so you can get an idea of what the underlying HTML looks like for
Gmail.  It is also included to somewhat document what the current interface needs to
manipulate to extract data from Gmail.

	<html><head><meta content="text/html; charset=UTF-8" http-equiv="content-type"></head>
	<script>D=(top.js&&top.js.init)?function(d){top.js.P(window,d)}:function(){};
	if(window==top){top.location='/gmail?search=inbox&view=tl&start=0&init=1&zx=VERSION + RANDOM 9 DIGIT NUMBER&fs=1';}
	</script><script><!--
	D(["v","fc5985703d8fe4f8"]
	);
	D(["p",["bx_hs","1"]
	,["bx_show0","1"]
	,["bx_sc","1"]
	,["sx_dn","username"]
	]
	);
	D(["i",0]
	);
	D(["qu","0 MB","1000 MB","0%","#006633"]
	);
	D(["ds",1,0,0,0,0,0]
	);
	D(["ct",[["label 1",1]
	,["label 2",0]
	,["label 3",1]
	]
	]
	);
	D(["ts",0,50,10,0,"Inbox","",13]
	);
	D(["t",["MSG ID",1,0,"\<b\>12:53am\</b\>","\<span id=\'_user_sender@domain.com\'\>Sender Name\</span\>
	","\<b\>&raquo;\</b\>&nbsp;","\<b\>Subject\</b\>","Blurb &hellip;",["label1","label 2"]
	,"attachment name1, attachment name2","MSG ID",0]
	]
	);

	D(["te"]);

	//--></script><script>var fp='';</script><script>var loaded=true;D(['e']);</script>

=head1 SAMPLE TEST SCRIPTS

below is a listing of some of the tests that I use as I test various features

	my ( $gmail ) = Gmail->new( 
			username => 'username', password => 'password', );

	### Prints out new messages attached to the first label
	my @labels = $gmail->get_labels();

	my $messages = $gmail->get_messages( label => $labels[0] );

	foreach ( @{ $messages } ) {
		if ( $_->{ 'new' } ) {
			print "Subject: " . $_->{ 'subject' } . " / Blurb: " . $_->{ 'blurb' } . "\n";
		}
	}
	###

	### Prints out all attachments
	my $messages = $gmail->get_messages();

	foreach ( @{ $messages } ) {
		my $email = $gmail->get_indv_email( msg => $_ );
		if ( defined( $email->{ $_->{ 'id' } }->{ 'attachments' } ) ) {
			foreach ( @{ $email->{ $_->{ 'id' } }->{ 'attachments' } } ) {
				print ${ $gmail->get_attachment( attachment => $_ ) } . "\n";
				if ( $gmail->error() ) {
					print $gmail->error_msg();
				}
			}
		}
	}
	###

	### Shows different ways to look through your email
	my $messages = $gmail->get_messages();

	print "By folder\n";
	foreach ( keys %Gmail::FOLDERS ) {
		my $messages = $gmail->get_messages( label => $Gmail::FOLDERS{ $_ } );
		print "\t$_:\n";
		if ( @{ $messages } ) {
			foreach ( @{ $messages } ) {
				print "\t\t$_->{ 'subject' }\n";
			}
		}
	}

	print "By label\n";
	foreach ( $gmail->get_labels() ) {
		my $messages = $gmail->get_messages( label => $_ );
		print "\t$_:\n";
		if ( @{ $messages } ) {
			foreach ( @{ $messages } ) {
				print "\t\t$_->{ 'subject' }\n";
			}
		}
	}

	print "All (Note: the All folder skips trash)";
	my $messages = $gmail->get_messages();
	if ( @{ $messages } ) {
		foreach ( @{ $messages } ) {
			print "\t\t$_->{ 'subject' }\n";
		}
	}
	###

=head1 TO-DO

Right now, this script has the ability to do the reading of the data, but there is
no ability to modify or create new data ( such as creating new labels or sending mail ).

Also, i dont like the way email is presented to the user ( its too messy and complicated )
I want individual email messages to be objects as well etc.

=head1 AUTHOR INFORMATION

Copyright 2004, Allen Holman.  All rights reserved.  

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

Address bug reports and comments to: mincus \at mincus \. com.  When sending
bug reports, please provide the version of gmail.pm, the version of
Perl and the name and version of the operating system you are using. 

=head1 CREDITS

I'd like to thank the following people who gave me a little direction in getting 
this module started (wether they know it or not)

Simon Drabble (Mail::Webmail::Yahoo)
Erik F. Kastner (WWW::Scraper::Gmail)

=head1 BUGS

Please report them.

=cut
