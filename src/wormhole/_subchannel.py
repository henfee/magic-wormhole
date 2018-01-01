from attr import attrs, attrib
from attr.validators import instance_of
from automat import MethodicalMachine
from . import _interfaces

@attrs

@implementer(_interfaces.ISubChannel)
class SubChannel(object):
    _id = attrib(validator=int)
    m = MethodicalMachine()
    set_trace = getattr(m, "_setTrace", lambda self, f: None)

    def __attrs_post_init__(self):
        #self._mailbox = None
        #self._pending_outbound = {}
        #self._processed = set()
        pass

    @m.state(initial=True)
    def idle(self): pass # pragma: no cover

    @m.state()
    def open(self): pass # pragma: no cover

    @m.state()
    def closing(): pass # pragma: no cover

    @m.state()
    def closed(): pass # pragma: no cover

    @m.input()
    def remote_open(self):
        pass

    @m.input()
    def remote_data(self, x):
        pass

    @m.input()
    def local_data(self, x):
        pass

    @m.input()
    def local_close(self):
        pass

    @m.input()
    def remote_close(self):
        pass

    @m.output()
    def send_close(self):
        pass

    # things that can happen when idle
    @m.output()
    def error_early_remote_data(self, data):
        raise Error
    @m.output()
    def error_early_local_data(self, data):
        raise Error
    @m.output()
    def error_early_local_close(self):
        raise Error
    @m.output()
    def error_early_remote_close(self):
        raise Error

    idle.upon(remote_open, enter=open, outputs=[])
    idle.upon(remote_data, enter=idle, outputs=[error_early_remote_data])
    idle.upon(local_data, enter=idle, outputs=[error_early_local_data])
    idle.upon(local_close, enter=idle, outputs=[error_early_local_close])
    idle.upon(remote_close, enter=idle, outputs=[error_early_remote_close])


    # things that can happen while open
    @m.output()
    def error_double_remote_open(self):
        raise Error
    @m.output()
    def accept_data(self, data):
        XXX
    @m.output()
    def send_data(self, data):
        XXX
    @m.output()
    def send_close(self):
        XXX
    @m.output()
    def close_subchannel(self):
        XXX

    open.upon(remote_open, enter=open, outputs=[error_double_remote_open])
    open.upon(remote_data, enter=open, outputs=[accept_data])
    open.upon(local_data, enter=open, outputs=[send_data])
    open.upon(local_close, enter=closing, outputs=[send_close])
    open.upon(remote_close, enter=closed, outputs=[close_subchannel])


    # things that can happen while closing
    @m.output()
    def error_double_remote_open(self):
        raise Error
    @m.output()
    def ignore_remote_data(self, data):
        pass
    @m.output()
    def error_late_local_data(self, data):
        raise Error
    @m.output()
    def error_double_local_close(self):
        raise Error
    @m.output()
    def finished_closing(self):
        XXX

    closing.upon(remote_open, enter=closing, outputs=[error_double_remote_open])
    closing.upon(remote_data, enter=closing, outputs=[ignore_remote_data])
    closing.upon(local_data, enter=closing, outputs=[error_late_local_data])
    closing.upon(local_close, enter=closing, outputs=[error_double_local_close])
    closing.upon(remote_close, enter=closed, outputs=[finished_closing])


    # things that can happen while closed
    @m.output()
    def error_reopened(self):
        raise Error
    @m.output()
    def error_late_remote_data(self, data):
        raise Error
    @m.output()
    def error_late_local_data(self, data):
        raise Error
    @m.output()
    def error_late_local_close(self):
        raise Error
    @m.output()
    def error_late_remote_close(self):
        raise Error

    closed.upon(remote_open, enter=closed, outputs=[error_reopened])
    closed.upon(remote_data, enter=closed, outputs=[error_late_remote_data])
    closed.upon(local_data, enter=closed, outputs=[error_late_local_data])
    closed.upon(local_close, enter=closed, outputs=[error_late_local_close])
    closed.upon(remote_close, enter=closed, outputs=[error_late_remote_close])


