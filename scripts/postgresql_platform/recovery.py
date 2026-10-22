"""Explicit isolated restore; never restore in place or remove an existing tree."""
import pathlib
import subprocess


def restore(domain, directory, target_time=None):
    if domain not in ('hertzbeat', 'vector', 'shared'):
        raise ValueError('unknown restore domain')
    destination = pathlib.Path(directory)
    if not destination.is_absolute() or destination.is_symlink() or not destination.name.startswith('lme-pg-restore-'):
        raise ValueError('restore requires a separate lme-pg-restore-* directory')
    if destination.exists() and any(destination.iterdir()):
        raise ValueError('restore destination must be fresh and empty')
    destination.mkdir(mode=0o700, parents=False, exist_ok=True)
    command = ['pgbackrest', '--stanza=' + domain, '--pg1-path=' + str(destination), '--archive-mode=off']
    if target_time:
        command += ['--type=time', '--target=' + target_time, '--target-action=shutdown']
    command += ['restore']
    subprocess.run(command, check=True)
    # Return a restored tree, not a promoted writer. Start isolated for readback
    # only using a distinct socket and no TCP listener during acceptance.
    return destination
