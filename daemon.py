"""Generic linux daemon base class for python 3.x."""

import os
import sys
import time
import atexit
import signal

class Daemon:
    """daemon class."""

    def __init__(self, config):
        self.progname = config['progname']
        self.pidfile = config['pidfile']
        self.logger = config['logger']
        self.foreground = config['foreground']

        # setup the signals
        signal.signal(signal.SIGUSR1, self.receive_signal) # dump the packet capture stats
        signal.signal(signal.SIGUSR2, self.receive_signal) # dump the mac dictionary
        signal.signal(signal.SIGHUP, self.receive_signal) # re-start
        signal.signal(signal.SIGQUIT, self.receive_signal) # nicely stop things
        signal.signal(signal.SIGTERM, self.receive_signal) # not-so-nice termination
    
    def daemonize(self):
        """deamonize function using the classic UNIX double fork mechanism."""
        
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit first parent
                sys.exit(0) 
        except OSError as err:
            message = 'fork #1 failed: {0}'.format(err)
            self.logger.info(message)
            sys.stderr.write(message)
            sys.exit(1)
    
        # decouple from parent environment
        os.chdir('/') 
        os.setsid() 
        os.umask(0) 
    
        # do second fork
        try: 
            pid = os.fork() 
            if pid > 0:
                # exit from second parent
                sys.exit(0) 
        except OSError as err:
            message = 'fork #2 failed: {0}'.format(err)
            self.logger.info(message)
            sys.stderr.write(message)
            sys.exit(1) 
    
        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = open(os.devnull, 'r')
        so = open(os.devnull, 'a+')
        se = open(os.devnull, 'a+')

        os.dup2(si.fileno(), sys.stdin.fileno())
        os.dup2(so.fileno(), sys.stdout.fileno())
        os.dup2(se.fileno(), sys.stderr.fileno())
    
        # write pidfile
        pid = self.create_pidfile()
        sys.stderr.write('deamonize2')
        return pid

    def create_pidfile(self):
        # write pidfile
        atexit.register(self.delete_pidfile)

        pid = str(os.getpid())
        try:
            with open(self.pidfile,'w+') as f:
                f.write(pid + '\n')
                f.close()
        except IOError:
            pid = None

        return pid

    def delete_pidfile(self):
        os.remove(self.pidfile)

    def check_pidfile(self):
        """Checks for the pid file."""
        try:
            with open(self.pidfile, 'r') as pf:
                pid = int(pf.read().strip())
                pf.close()
        except IOError:
            pid = None

        return pid

    def start(self, restart = False):
        """Start the daemon."""

        # Check for a pidfile to see if the daemon already runs
        pid = self.check_pidfile()
    
        # is this a restart and not a first run?
        if restart:
            message = 'restaring the daemon'.format(pid)
            self.logger.info(message)

        if pid:
            message = "pidfile {0} (pid={1}) already exist. " \
                      + "daemon already running?\n".format(self.pidfile, pid)
            self.logger.info(message)
            sys.stderr.write(message)
            sys.exit(1)
        else:            
            # start in foreground of background?
            if (self.foreground):
                sys.stderr.write('foreground')
                pid = self.create_pidfile()
                message = 'started in foreground pid={}'.format(pid)
                self.logger.info(message)
                self.run()
            else:
                sys.stderr.write('background')
                pid = self.daemonize()
                message = 'started daemon pid={}'.format(pid)
                self.logger.info(message)
                self.run()

    def stop(self):
        """Stop the daemon."""

        # get the pid from the pidfile
        try:
            with open(self.pidfile,'r') as pf:
                pid = int(pf.read().strip())
        except IOError:
            pid = None
    
        if not pid:
            message = "pidfile does not exist. " + \
                    "daemon not running?"
            self.logger.info(message)
            sys.stderr.write(message + '\n')
            return # not an error in a restart

        message = 'stopping daemon pid={}'.format(pid)
        self.logger.info(message)
        
        # try killing the daemon process    
        try:
            while 1:
                os.kill(pid, signal.SIGTERM)
                time.sleep(0.1)
        except OSError as err:
            e = str(err.args)
            if e.find("No such process") > 0:
                if os.path.exists(self.pidfile):
                    os.remove(self.pidfile)
            else:
                self.logger.info('stopped daemon, pid=(%d)' % pid)
                sys.exit(1)


    def restart(self):
        """Restart the daemon."""
        message = 'restarting daemon'
        self.logger.info(message)
        
        self.stop()
        pid = self.start(True)
        message = 'restarted daemon pid={}'.format(pid)
        self.logger.info(message)


    def status(self):
        """return the status of the damon"""
        pid = Daemon.check_pidfile(self)
        if pid:
            print('%s running (pid=%d)' % (self.progname, pid))
        else:
            print('%s is not runing' % (self.progname))

    def run(self):
        """ overload this in your class """
