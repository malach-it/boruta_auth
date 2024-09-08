defmodule Boruta.Migrations.VerifiablePresentationDefinitions do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20240908075843_add_presentation_definition_to_oauth_tokens.exs
        alter table(:oauth_tokens) do
          add :presentation_definition, :jsonb
        end
      end
    end
  end
end

