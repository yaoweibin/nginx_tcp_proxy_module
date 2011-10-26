package Test::Nginx::Util;

use strict;
use warnings;

our $VERSION = '0.08';

use base 'Exporter';

use POSIX qw( SIGQUIT SIGKILL SIGTERM );
use File::Spec ();
use HTTP::Response;
use Module::Install::Can;
use Cwd qw( cwd );
use List::Util qw( shuffle );

our $NoNginxManager = 0;
our $Profiling = 0;

our $RepeatEach = 1;
our $MAX_PROCESSES = 10;

our $ForkManager;

if ($Profiling) {
    eval "use Parallel::ForkManager";
    if ($@) {
        die "Failed to load Parallel::ForkManager: $@\n";
    }
    $ForkManager = new Parallel::ForkManager($MAX_PROCESSES);
}

our $Workers                = 2;
our $WorkerConnections      = 1024;
our $LogLevel               = 'debug';
our $MasterProcessEnabled   = 'off';
our $DaemonEnabled          = 'on';
our $ServerPort             = 1984;
our $ServerPortForClient    = 1984;


sub repeat_each (@) {
    if (@_) {
        $RepeatEach = shift;
    } else {
        return $RepeatEach;
    }
}

sub worker_connections (@) {
    if (@_) {
        $WorkerConnections = shift;
    } else {
        return $WorkerConnections;
    }
}

sub workers (@) {
    if (@_) {
        #warn "setting workers to $_[0]";
        $Workers = shift;
    } else {
        return $Workers;
    }
}

sub log_level (@) {
    if (@_) {
        $LogLevel = shift;
    } else {
        return $LogLevel;
    }
}

sub master_on () {
    $MasterProcessEnabled = 'on';
}

sub master_process_enabled (@) {
    if (@_) {
        $MasterProcessEnabled = shift() ? 'on' : 'off';
    } else {
        return $MasterProcessEnabled;
    }
}

our @EXPORT_OK = qw(
    setup_server_root
    write_config_file
    get_canon_version
    get_nginx_version
    trim
    show_all_chars
    parse_headers
    run_tests
    $ServerPortForClient
    $ServerPort
    $NginxVersion
    $PidFile
    $ServRoot
    $ConfFile
    $RunTestHelper
    $NoNginxManager
    $RepeatEach
    worker_connections
    workers
    master_on
    config_preamble
    repeat_each
    master_process_enabled
    log_level
);


if ($Profiling) {
    $DaemonEnabled          = 'off';
    $MasterProcessEnabled   = 'off';
}

our $ConfigPreamble = '';

sub config_preamble ($) {
    $ConfigPreamble = shift;
}

our $RunTestHelper;

our $NginxVersion;
our $NginxRawVersion;
our $TODO;

#our ($PrevRequest, $PrevConfig);

our $ServRoot   = File::Spec->catfile(cwd(), 't/servroot');
our $LogDir     = File::Spec->catfile($ServRoot, 'logs');
our $ErrLogFile = File::Spec->catfile($LogDir, 'error.log');
our $AccLogFile = File::Spec->catfile($LogDir, 'access.log');
our $HtmlDir    = File::Spec->catfile($ServRoot, 'html');
our $ConfDir    = File::Spec->catfile($ServRoot, 'conf');
our $ConfFile   = File::Spec->catfile($ConfDir, 'nginx.conf');
our $PidFile    = File::Spec->catfile($LogDir, 'nginx.pid');

sub run_tests () {
    $NginxVersion = get_nginx_version();

    if (defined $NginxVersion) {
        #warn "[INFO] Using nginx version $NginxVersion ($NginxRawVersion)\n";
    }

    for my $block (shuffle Test::Base::blocks()) {
        #for (1..3) {
            run_test($block);
        #}
    }

    if ($Profiling) {
        $ForkManager->wait_all_children;
    }
}

sub setup_server_root () {
    if (-d $ServRoot) {
        #sleep 0.5;
        #die ".pid file $PidFile exists.\n";
        system("rm -rf t/servroot > /dev/null") == 0 or
            die "Can't remove t/servroot";
        #sleep 0.5;
    }
    mkdir $ServRoot or
        die "Failed to do mkdir $ServRoot\n";
    mkdir $LogDir or
        die "Failed to do mkdir $LogDir\n";
    mkdir $HtmlDir or
        die "Failed to do mkdir $HtmlDir\n";

    my $index_file = "$HtmlDir/index.html";

    my $out;

    open $out, ">$index_file" or
        die "Can't open $index_file for writing: $!\n";

    print $out '<html><head><title>It works!</title></head><body>It works!</body></html>';

    close $out;

    mkdir $ConfDir or
        die "Failed to do mkdir $ConfDir\n";

    my $ssl_crt = "$ConfDir/ssl.crt";

    open $out, ">$ssl_crt" or
        die "Can't open $ssl_crt for writing: $!\n";

    print $out <<_EOC_;
-----BEGIN CERTIFICATE-----
MIIClzCCAgACCQCKlE5LBV9thDANBgkqhkiG9w0BAQUFADCBjzELMAkGA1UEBhMC
Q04xEjAQBgNVBAgTCVpoZSBKaWFuZzERMA8GA1UEBxMISGFuZ3pob3UxFDASBgNV
BAoTC05ldGVhc2UgTHRkMQswCQYDVQQLEwJJVDEUMBIGA1UEAxMLbml4Y3JhZnQu
aW4xIDAeBgkqhkiG9w0BCQEWEWFkbWluQG5peGNyYWZ0LmluMB4XDTEwMDkwMzA2
NTk1OFoXDTExMDkwMzA2NTk1OFowgY8xCzAJBgNVBAYTAkNOMRIwEAYDVQQIEwla
aGUgSmlhbmcxETAPBgNVBAcTCEhhbmd6aG91MRQwEgYDVQQKEwtOZXRlYXNlIEx0
ZDELMAkGA1UECxMCSVQxFDASBgNVBAMTC25peGNyYWZ0LmluMSAwHgYJKoZIhvcN
AQkBFhFhZG1pbkBuaXhjcmFmdC5pbjCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkC
gYEAyGpGE56F6KcC2EnU/Nf0JWUrwApvJjDc6yYYpZWtYoSHdwDMwnbF7nQbBTjQ
Ew2C23RvYlrpxaEBvIi6y4CnE98AvYfI50dDtT1cO4lBoDugbIgtryZywXHL2TbU
ZQ2eJc+6vJClVGc1LjZ10ZzAAt63VroO2FAh/fZUZPXEzUMCAwEAATANBgkqhkiG
9w0BAQUFAAOBgQA7x4lND+41f5ihXgd4cAM8W4GQ+mpQpKt+BRxto740SdUL+DNt
PmMLoqw7Pis9Pkn7PQj/O3vJkx4Bfzmrm/s0bX82mYJSjPz8XL42n7n3Cg8HCCLG
3JeNnJc75EYwpqf7tyauMUZSACBIGXeteu4OyZ4j/qObJ3GyKVFqR/PJrQ==
-----END CERTIFICATE-----
_EOC_
    close $out;

    my $ssl_key = "$ConfDir/ssl.key";

    open $out, ">$ssl_key" or
        die "Can't open $ssl_key for writing: $!\n";

    print $out <<_EOC_;
-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDIakYTnoXopwLYSdT81/QlZSvACm8mMNzrJhilla1ihId3AMzC
dsXudBsFONATDYLbdG9iWunFoQG8iLrLgKcT3wC9h8jnR0O1PVw7iUGgO6BsiC2v
JnLBccvZNtRlDZ4lz7q8kKVUZzUuNnXRnMAC3rdWug7YUCH99lRk9cTNQwIDAQAB
AoGAdWCAoFb0mHjQGrrLKjaUgB5LzFKQHG77xCDwyHHsNUnnSNRIGBCWBf0sIhfP
DYmZPUxpO9KBHcUZjkEKHcvAjcGUDdm2HoXYt9V5peAYqdbYOZ/cfEGRzRVTDcy4
etDvmNqj4t6F9nuq5Rkx7wg/mkGp7Jj0JC5nn7gIcpBiAVkCQQD12rXZ9nhvwKuD
yF+7lUnmIHRePjtJQcK4+xS9F4UgPiL/cZ3JRcZeo2bagE5ye+mLeGuL3zDOsbY1
/4dzfulPAkEA0K+HK5rESxFuCOH/XhY85jrt1P2ICFfr1S4zi9Sijquczo9XXHJx
cXrj4nOiIzmvLSk6MjrMYNhwW7Sycbw3zQJAD7MUs8N6c2BxU2wDOP5ShsCBzdbZ
gFcTsS5PZ7fNx35QS9GcitLK1RZIJiHVYJgrFL3u2DK7cieFBDO6GZT8HwJBAI7I
2rqaDV6zkU8gmqKcopSAk4Qc6HuU9LaLAxfUqFjn0MWATCzj3PzhMZUau0BQ0qwa
vkfp9Tb6QH5ut32cY60CQQCycpFyUhKpY4l81On7LK3Nq2z0+RZ85MbCIkQkQn2H
4fqfNoKrLPP2JrMCYrvjrc+hez/ffd3u2II/93kksfCx
-----END RSA PRIVATE KEY-----
_EOC_
    close $out;

}

sub write_config_file ($$) {
    my ($config, $http_config) = @_;

    if (!defined $config) {
        $config = '';
    }

    if (!defined $http_config) {
        $http_config = '';
    }

    open my $out, ">$ConfFile" or
        die "Can't open $ConfFile for writing: $!\n";
    print $out <<_EOC_;
worker_processes  $Workers;
daemon $DaemonEnabled;
master_process $MasterProcessEnabled;
error_log $ErrLogFile $LogLevel;
pid       $PidFile;

tcp {

ssl_certificate "$ConfDir/ssl.crt";
ssl_certificate_key "$ConfDir/ssl.key";

# Begin test case config...
    $config
# End test case config.
}

events {
    worker_connections  $WorkerConnections;
}

_EOC_
    close $out;
}

sub get_canon_version (@) {
    sprintf "%d.%03d%03d", $_[0], $_[1], $_[2];
}

sub get_nginx_version () {
    my $out = `nginx -V 2>&1`;
    if (!defined $out || $? != 0) {
        warn "Failed to get the version of the Nginx in PATH.\n";
    }
    if ($out =~ m{nginx/(\d+)\.(\d+)\.(\d+)}s) {
        $NginxRawVersion = "$1.$2.$3";
        return get_canon_version($1, $2, $3);
    }
    warn "Failed to parse the output of \"nginx -V\": $out\n";
    return undef;
}

sub get_pid_from_pidfile ($) {
    my ($name) = @_;
    open my $in, $PidFile or
        Test::More::BAIL_OUT("$name - Failed to open the pid file $PidFile for reading: $!");
    my $pid = do { local $/; <$in> };
    #warn "Pid: $pid\n";
    close $in;
    $pid;
}

sub trim ($) {
    (my $s = shift) =~ s/^\s+|\s+$//g;
    $s =~ s/\n/ /gs;
    $s =~ s/\s{2,}/ /gs;
    $s;
}

sub show_all_chars ($) {
    my $s = shift;
    $s =~ s/\n/\\n/gs;
    $s =~ s/\r/\\r/gs;
    $s =~ s/\t/\\t/gs;
    $s;
}

sub parse_headers ($) {
    my $s = shift;
    my %headers;
    open my $in, '<', \$s;
    while (<$in>) {
        s/^\s+|\s+$//g;
        my ($key, $val) = split /\s*:\s*/, $_, 2;
        $headers{$key} = $val;
    }
    close $in;
    return \%headers;
}

sub run_test ($) {
    my $block = shift;
    my $name = $block->name;

    my $config = $block->config;
    if (!defined $config) {
        Test::More::BAIL_OUT("$name - No '--- config' section specified");
        #$config = $PrevConfig;
        die;
    }

    my $skip_nginx = $block->skip_nginx;
    my ($tests_to_skip, $should_skip, $skip_reason);
    if (defined $skip_nginx) {
        if ($skip_nginx =~ m{
                ^ \s* (\d+) \s* : \s*
                    ([<>]=?) \s* (\d+)\.(\d+)\.(\d+)
                    (?: \s* : \s* (.*) )?
                \s*$}x) {
            $tests_to_skip = $1;
            my ($op, $ver1, $ver2, $ver3) = ($2, $3, $4, $5);
            $skip_reason = $6;
            #warn "$ver1 $ver2 $ver3";
            my $ver = get_canon_version($ver1, $ver2, $ver3);
            if ((!defined $NginxVersion and $op =~ /^</)
                    or eval "$NginxVersion $op $ver")
            {
                $should_skip = 1;
            }
        } else {
            Test::More::BAIL_OUT("$name - Invalid --- skip_nginx spec: " .
                $skip_nginx);
            die;
        }
    }
    if (!defined $skip_reason) {
        $skip_reason = "various reasons";
    }

    my $todo_nginx = $block->todo_nginx;
    my ($should_todo, $todo_reason);
    if (defined $todo_nginx) {
        if ($todo_nginx =~ m{
                ^ \s*
                    ([<>]=?) \s* (\d+)\.(\d+)\.(\d+)
                    (?: \s* : \s* (.*) )?
                \s*$}x) {
            my ($op, $ver1, $ver2, $ver3) = ($1, $2, $3, $4);
            $todo_reason = $5;
            my $ver = get_canon_version($ver1, $ver2, $ver3);
            if ((!defined $NginxVersion and $op =~ /^</)
                    or eval "$NginxVersion $op $ver")
            {
                $should_todo = 1;
            }
        } else {
            Test::More::BAIL_OUT("$name - Invalid --- todo_nginx spec: " .
                $todo_nginx);
            die;
        }
    }

    if (!defined $todo_reason) {
        $todo_reason = "various reasons";
    }

    if (!$NoNginxManager && !$should_skip) {
        my $nginx_is_running = 1;
        if (-f $PidFile) {
            my $pid = get_pid_from_pidfile($name);
            if (!defined $pid or $pid eq '') {
                undef $nginx_is_running;
                goto start_nginx;
            }

            if (system("ps $pid > /dev/null") == 0) {
                #warn "found running nginx...";
                write_config_file($config, $block->http_config);
                if (kill(SIGQUIT, $pid) == 0) { # send quit signal
                    #warn("$name - Failed to send quit signal to the nginx process with PID $pid");
                }
                sleep 0.02;
                if (system("ps $pid > /dev/null") == 0) {
                    #warn "killing with force...\n";
                    kill(SIGKILL, $pid);
                    sleep 0.02;
                }
                undef $nginx_is_running;
            } else {
                unlink $PidFile or
                    die "Failed to remove pid file $PidFile\n";
                undef $nginx_is_running;
            }
        } else {
            undef $nginx_is_running;
        }

start_nginx:

        unless ($nginx_is_running) {
            #system("killall -9 nginx");

            #warn "*** Restarting the nginx server...\n";
            setup_server_root();
            write_config_file($config, $block->http_config);
            if ( ! Module::Install::Can->can_run('nginx') ) {
                Test::More::BAIL_OUT("$name - Cannot find the nginx executable in the PATH environment");
                die;
            }
        #if (system("nginx -p $ServRoot -c $ConfFile -t") != 0) {
        #Test::More::BAIL_OUT("$name - Invalid config file");
        #}
        #my $cmd = "nginx -p $ServRoot -c $ConfFile > /dev/null";
            my $cmd;
            if ($NginxVersion >= 0.007053) {
                $cmd = "nginx -p $ServRoot/ -c $ConfFile > /dev/null";
            } else {
                $cmd = "nginx -c $ConfFile > /dev/null";
            }

            if ($Profiling) {
                my $pid = $ForkManager->start;
                if (!$pid) {
                    # child process
                    if (system($cmd) != 0) {
                        Test::More::BAIL_OUT("$name - Cannot start nginx using command \"$cmd\".");
                    }

                    $ForkManager->finish; # terminate the child process
                }
            } else {
                if (system($cmd) != 0) {
                    Test::More::BAIL_OUT("$name - Cannot start nginx using command \"$cmd\".");
                }
            }

            sleep 10;
        }
    }

    my $i = 0;
    while ($i++ < $RepeatEach) {
        if ($should_skip) {
            SKIP: {
                Test::More::skip("$name - $skip_reason", $tests_to_skip);

                $RunTestHelper->($block);
            }
        } elsif ($should_todo) {
            TODO: {
                local $TODO = "$name - $todo_reason";

                $RunTestHelper->($block);
            }
        } else {
            $RunTestHelper->($block);
        }
    }

    if (defined $block->quit && $Profiling) {
        warn "Found quit...";
        if (-f $PidFile) {
            my $pid = get_pid_from_pidfile($name);
            if (system("ps $pid > /dev/null") == 0) {
                write_config_file($config, $block->http_config);
                if (kill(SIGQUIT, $pid) == 0) { # send quit signal
                    #warn("$name - Failed to send quit signal to the nginx process with PID $pid");
                }
                sleep 0.02;
                if (system("ps $pid > /dev/null") == 0) {
                    #warn "killing with force...\n";
                    kill(SIGKILL, $pid);
                    sleep 0.02;
                }
            } else {
                unlink $PidFile or
                    die "Failed to remove pid file $PidFile\n";
            }
        }
    }
}

1;
