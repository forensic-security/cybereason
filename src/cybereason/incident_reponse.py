from typing import TYPE_CHECKING

from .exceptions import authz, min_version, ResourceNotFoundError, ServiceDisabled
from ._typing import CybereasonProtocol

if TYPE_CHECKING:
    from typing import Any, Literal, Optional
    from os import PathLike


class IncidentResponseMixin(CybereasonProtocol):
    @min_version(21, 1, 81)
    @authz('Responder L2')
    async def get_irtools_packages(self) -> 'Any':
        '''Retrieves a list of previously uploaded packages from your
        environment.
        '''
        return await self.get('irtools/packages')

    @min_version(21, 1, 81)
    @authz('Responder L2')
    async def upload_irtools_package(
        self,
        name:        str,
        filepath:    'PathLike',
        description: str,
        run_command: 'Optional[str]' = None,
        output_dir:  'Optional[str]' = None,
        platform:    'Optional[Literal["x86", "x64"]]' = None,
    ) -> None:
        '''Enables you to upload a package for a third-party IR tool to
        your Cybereason platform or upgrade a previously uploaded package,
        and then deploy that package to selected machines.

        The maximum file size for a tool package file is 100 MB.

        Args:
            name: The name for the package. You must use a unique name.
            info: The full file name for the package file.
            description: A description for the tool.
            run_command: An appropriate command for the tool when it runs.
            output_dir: The folder to which to send the output from the
                tool's execution.
            platform: OS bitness: either ``x64`` or ``x86``.
        '''
        data = {
            'pacakgeName':        name,
            'packageOSInfoList':  {'osTypeGroup': 'WINDOWS_TYPES'},
            'packageContentType': 'FILE',
            'posixPermissions':   'EXECUTE',
            'description':        description,
        }

        if platform:
            try:
                _platform = dict(x86='ARCH_X86', x64='ARCH_AMD64')[platform]
            except KeyError:
                raise ValueError("Platform must be 'x86' or 'x64'") from None
            data['packageOSInfoList']['platform'] = _platform  # type: ignore

        if run_command or output_dir:
            data['packageRunConfiguration'] = {}
            if run_command:
                data['packageRunConfiguration']['runCommand'] = run_command  # type: ignore
            if output_dir:
                data['packageRunConfiguration']['outputDir'] = output_dir  # type: ignore

        try:
            package_info = 'file', open(filepath, 'rb'), 'application/octet-stream'
        except FileNotFoundError:
            raise ResourceNotFoundError(filepath) from None
        files = {'packageInfo': package_info}

        try:
            return await self.post('irtools/upload', data=data, files=files)
        except ServiceDisabled:
            raise ServiceDisabled('Packages delivery service is disabled') from None

    async def get_credentials(self) -> 'Any':
        '''Retrieves credentials for a predefined GCP bucket of your
        environment that you can use to access the tool results output.
        '''
        # TODO
        return await self.get('irtools/credentials')

    @min_version(21, 2, 221)
    @authz('Responder L2')
    async def get_forensics_tools(self):
        '''Retrieves a list of supported forensic data ingestion tools.
        '''
        return await self.get('forensics/forensicTools')

    # TODO: forensics tools methods
