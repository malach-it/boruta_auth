defmodule Boruta.Migrations.OauthTokenResource do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        alter table(:oauth_tokens) do
          add :resource, :string
        end
      end
    end
  end
end
