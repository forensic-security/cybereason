from datetime import datetime, timezone
import logging
import re

log = logging.getLogger(__name__)


split_re = re.compile(r'((CEF:\d+)([^=\\]+\|){,7})(.*)')
header_re = re.compile(r'(?<!\\)\|')
extension_re = re.compile(r'([^=\s]+)=((?:[\\]=|[^=])+)(?:\s|$)')


# https://nest.cybereason.com/documentation/product-documentation/212/syslog-messages
# https://nest.cybereason.com/documentation/product-documentation/221/syslog-extension-fields
def cefparse(string, strict=False):
    '''Parse a string in CEF format and return a dict with the headers
    and the extension data.

    https://community.microfocus.com/cfs-file/__key/communityserver-wikis-components-files/00-00-00-00-23/3731.CommonEventFormatV25.pdf
    '''

    # split the string into header and extension
    try:
        header, *_, extension = split_re.search(string).groups()
    except AttributeError:
        log.warning('Could not parse CEF record: %s', string)
        return None

    # split the header
    spl = header_re.split(header)[0:-1]

    # spec does not allow any blanks in the required headers, but
    # Cybereason logs do not provide a DeviceVersion value
    if '' in spl and strict:
        log.warning('Blank field(s) in CEF header')
        return None

    values = {
        'DeviceVendor': spl[1],
        'DeviceProduct': spl[2],
        'DeviceVersion': spl[3],
        'DeviceEventClassID': spl[4],
        'Name': spl[5],
    }
    if len(spl) > 6:
        values['Severity'] = int(spl[6])

    # ignore syslog prefix
    cef_start = spl[0].find('CEF')
    if cef_start == -1:
        log.warning('Error parsing log: %s', string)
        return None
    _, values['CEFVersion'] = spl[0][cef_start:].split(':')

    # find key=value pairs
    values.update({k: v for k, v in extension_re.findall(extension)})

    # replace the custom fields with their labels
    for key in list(values.keys()):
        if key[-5:] == 'Label':
            label = key[:-5]
            try:
                values[values[key]] = values[label]
                del values[label]
                del values[key]
            except KeyError:
                if not strict:
                    values[values[key]] = ''
                    del values[key]

    return values


CEF_DATETIME_FMT = '%b %d %Y, %H:%M:%S %Z'


def parse_cef_datetime(dt, to_str: bool = False):
    dt = datetime.strptime(dt, CEF_DATETIME_FMT).replace(tzinfo=timezone.utc)
    return dt.isoformat() if to_str else dt
