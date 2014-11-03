defmodule PlugBasicAuth.Helpers do
  defmacro __using__(opts) do
    quote do
      import unquote(__MODULE__)
      @before_compile unquote(__MODULE__)
    end
  end
  
  defmacro __before_compile__(_) do
    quote do
      PlugBasicAuth.Helpers.auth _ do
        true
      end
    end
  end

  defmacro auth(path, contents) do
    {_vars, match} = Plug.Router.Utils.build_match(path)
    quote do
      def do_auth(unquote(match)) do
        fn (var!(conn),var!(opts)) -> unquote(contents) end
      end
    end
  end
end

defmodule PlugBasicAuth do
  import Logger

  import Plug.Conn, only: [get_req_header:  2,
                           put_resp_header: 3,
                           send_resp:       3,
                           halt:            1]
  

  def init(opts) do
    Keyword.fetch!(opts, :module)
  end

  def call(conn, mod) do
    Logger.info("Starting call")
    {conn, creds} = conn |> get_auth_header |> parse_auth
    ret = mod.do_auth(conn.path_info).(conn, creds)
    if ret[:do] == false do
      conn
      |> put_resp_header("Www-Authenticate", "Basic realm=\"Private Area\"")
      |> send_resp(401, "")
      |> halt    
    else
      conn
    end
  end

  defp get_auth_header(conn) do
    auth = get_req_header(conn, "authorization")
    {conn, auth}
  end

  defp parse_auth({conn, ["Basic " <> encoded_creds | _]}) do
    {:ok, decoded_creds} = Base.decode64(encoded_creds)
    {conn, decoded_creds}
  end
  defp parse_auth({conn, _}), do: {conn, nil}

  defp respond_with_login(conn) do
    conn
    |> put_resp_header("Www-Authenticate", "Basic realm=\"Private Area\"")
    |> send_resp(401, "")
    |> halt
  end
end
