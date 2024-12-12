defmodule Boruta.Oauth.TokenGenerator do
  @moduledoc """
  Behaviour to implement utilities to generate token value. This must be implemented in the module configured as `token_generator` set in `config.exs`
  """

  @doc """
  Generates a token value from token entity.
  """
  @callback generate(type :: :access_token | :refresh_token, token :: struct()) ::
              value :: String.t()

  @doc """
  Generates a secret from client entity.
  """
  @callback secret(client :: struct()) :: value :: String.t()

  @callback tx_code_input_mode() :: tx_code_input_mode :: String.t()

  @callback tx_code_length() :: tx_code_length :: integer()
end
