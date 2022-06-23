from typing import TYPE_CHECKING
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path
from io import StringIO
import logging
import json
import gzip
import re

log = logging.getLogger(__name__)

if TYPE_CHECKING:
    from typing import Any, Dict, Iterator, List
    from os import PathLike


DT = r'\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3}'
LV = r'(DEBUG|INFO|WARN|ERROR)'


class ServerLogParser:
    logs = {
        'error':  {'parser': 'log2', 'rotation': 'seq'},
        'server': {'parser': 'log2', 'rotation': 'seq'},
    }

    def __init__(self, folder: 'PathLike') -> None:
        self.folder = Path(folder).resolve()

    @cached_property
    def pattern_2(self):
        # XXX: excludes stack traces
        return re.compile(
            rf'^(?P<timestamp>{DT})\s+?'
            r'(?P<exec>\[.*?\])?\s*?'
            rf'(?P<level>{LV})\s+'
            r'(?P<logger>.*?):\d+\s+-\s+'
            r'(?P<message>.*?$)',
        re.M)

    def parse(self, logname: str, *, rotated: bool=False) -> 'Iterator[Dict[str, Any]]':
        try:
            parser = self.logs.get(logname, {})['parser']
        except KeyError:
            log.error('Parser not implemented for %r', logname)
            return

        filepath = self.folder / f'{logname}.log'
        log.debug('Parsing %r', filepath.name)

        for entry in getattr(self, parser)(open(filepath), logname):
            yield entry

        if rotated:
            for archive in self._get_rotated(logname):
                log.debug('Parsing %r', archive.name)
                with gzip.GzipFile(archive, mode='r') as f:
                    buffer = StringIO(f.read().decode())
                    for entry in getattr(self, parser)(buffer, logname):
                        yield entry

    def _get_rotated(self, logname) -> 'List[Path]':
        '''Returns the rotated logs in order.
        '''
        rotation = self.logs[logname].get('rotation')
        archives = sorted(list(self.folder.glob(f'{logname}[-.]*.log.gz')))

        if rotation == 'seq':
            ptrn = re.compile(r'(\d+)').search
            sort = lambda x: int(ptrn(x.stem).group(0))
            archives = sorted(archives, key=sort)

        return reversed(archives)

    @staticmethod
    def log_datetime(dt):
        fmt = '%Y-%m-%d %H:%M:%S,%f'
        return datetime.strptime(f'{dt:0<26}', fmt).replace(tzinfo=timezone.utc)

    def _log(self, pattern, buffer, logtype):
        for match in pattern.finditer(buffer.read()):
            msg = match.groupdict()
            msg['timestamp'] = self.log_datetime(msg['timestamp'])
            msg['original'] = match.group(0)
            yield msg

    def log2(self, buffer, logtype):
        yield from self._log(self.pattern_2, buffer, logtype)
