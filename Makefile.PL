use ExtUtils::MakeMaker;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    NAME              => 'Mail::Webmail::Gmail',
    VERSION_FROM      => 'lib/Mail/Webmail/Gmail.pm', # finds $VERSION
    PREREQ_PM         => {
        LWP::UserAgent  => 0,
        HTTP::Headers   => 0,
        HTTP::Cookies   => 0,
        Crypt::SSLeay   => 0,
        Exporter        => 0,
        lib             => 0,
        strict          => 0,
}, # e.g., Module::Name => 1.1
    ($] >= 5.005 ?     ## Add these new keywords supported since 5.005
      ( AUTHOR         => 'Allen Holman (mincus) mincus@mincus.com') : ()),
);
