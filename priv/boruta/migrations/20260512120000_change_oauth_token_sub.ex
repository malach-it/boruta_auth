defmodule Boruta.Migrations.ChangeOauthTokenSub do
  @moduledoc false

  defmacro __using__(_args) do
    quote do
      def change do
        # 20240228103215_change_oauth_token_sub.exs
        alter table(:oauth_tokens) do
          modify(:sub, :text, from: :string)
        end
      end
    end
  end
end
