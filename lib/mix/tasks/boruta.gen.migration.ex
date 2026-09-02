# Portions of this file are based on Ecto SQL's ecto.gen.migration task.
# Copyright (c) 2012 Plataformatec
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use those portions except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This file has been modified for Boruta. Boruta's modifications are licensed
# under the MIT License found in the repository's LICENSE file.

defmodule Mix.Tasks.Boruta.Gen.Migration do
  @moduledoc """
  Migration task for Boruta.

  Creates `oauth_clients`, `oauth_scopes` and `oauth_tokens` tables.

  > __Note__: This task will create migration files to keep your integration up to date by checking migration file and module names to create missing ones.
  > Thus it is not recommended to change naming since it will recreate the migration in further runs.

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

    Enum.each(repos, fn repo ->
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
