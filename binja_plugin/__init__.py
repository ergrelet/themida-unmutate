from binaryninja import PluginCommand  # type:ignore

from . import actions, plugin

plugin_commands = [
    (
        f"{plugin.NAME}\\Deobfuscate mutated code from this address",
        "Deobfuscate mutated code from this address",
        PluginCommand.register_for_address,
        actions.deobfuscate_at_address,
    ),
]

for (command_name, command_description, command_registrator, command_action) in plugin_commands:
    command_registrator(name=command_name, description=command_description, action=command_action)
