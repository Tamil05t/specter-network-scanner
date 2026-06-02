from click.testing import CliRunner
import main

runner = CliRunner()
result = runner.invoke(main.cli, ["--config", "config.yaml", "--version"])
print('exit_code=', result.exit_code)
print('output=')
print(result.output)
print('excinfo=', result.excinfo)
if result.exception:
    import traceback
    traceback.print_exception(result.exception, result.exception, result.exception.__traceback__)
