defmodule Boruta.VerifiablePresentations do
  @moduledoc false

  alias Boruta.Oauth.Scope

  # TODO perform client metadata checks
  def check_client_metadata(_client_metadata), do: :ok

  def response_types(scope, presentation_configuration) do
    case Enum.any?(Map.keys(presentation_configuration), fn presentation_identifier ->
      Enum.member?(Scope.split(scope), presentation_identifier)
    end) do
      true -> ["vp_token"]
      false -> ["id_token"]
    end
  end
end
