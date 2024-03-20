defmodule Mix.Tasks.Boruta.Gen.Migration do
  @moduledoc """
  Migration task for Boruta.

  Creates `oauth_clients`, `oauth_scopes` and `oauth_tokens` tables.

  > __Note__: This task will create migration files to keep your integration up to date by checking migration file and module names to create missing ones.
  > Thus it is not recommended to change naming since it will recreate the migration in further runs.

  ## Usage statistics gathering
  This task will trigger a REPL to gather statistical info from your usage of the library. The owners are thankful to you for providing those informations since it helps better maintain the product.

  ## Examples
  ```
  mix boruta.gen.migration
  ```
  """

  use Mix.Task

  import Mix.Generator
  import Mix.Ecto
  import Mix.EctoSQL

  @shortdoc "Generates Boruta migrations"

  @doc false
  def run(args) do
    no_umbrella!("boruta.gen.migration")
    repos = parse_repo(args)

    Enum.map(repos, fn repo ->
      ensure_repo(repo, args)

      {:ok, migration_paths} =
        :code.priv_dir(:boruta)
        |> Path.join("boruta/migrations")
        |> File.ls()

      migration_paths
      |> Enum.sort()
      |> Enum.with_index()
      |> Enum.map(&create_migration_file(repo, &1))
    end)
  end

  defp create_migration_file(repo, {original_path, index}) do
    filename = Path.basename(original_path, ".ex")
    [_filename, basename] = Regex.run(~r/\d{14}_(.+)/, filename)

    migration_name = Macro.camelize(basename)
    timestamp = DateTime.utc_now() |> DateTime.add(index) |> Calendar.strftime("%Y%m%d%H%M%S")

    path = Path.join(source_repo_priv(repo), "migrations")
    file = Path.join(path, "#{timestamp}_#{basename}.exs")

    assigns = [
      mod: Module.concat([repo, Migrations, migration_name]),
      migration_name: migration_name
    ]

    fuzzy_path = Path.join(path, "*_#{basename}.exs")

    if Enum.empty?(Path.wildcard(fuzzy_path)) do
      create_file(file, migration_template(assigns))
    end
  end

  defp migration_module do
    case Application.get_env(:ecto_sql, :migration_module, Ecto.Migration) do
      migration_module when is_atom(migration_module) -> migration_module
      other -> Mix.raise("Expected :migration_module to be a module, got: #{inspect(other)}")
    end
  end

  embed_template(:migration, """
  defmodule <%= inspect @mod %> do
    use <%= inspect migration_module() %>

    use Boruta.Migrations.<%= @migration_name %>
  end
  """)
end
