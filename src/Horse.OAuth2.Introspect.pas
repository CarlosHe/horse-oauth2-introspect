unit Horse.OAuth2.Introspect;

interface

uses

  Horse,
  System.Generics.Collections;

type

  THorseOAuth2IntrospectConfig = class
  private
    FHost: string;
    FPath: string;
    FUser: string;
    FPassword: string;
  public
    class function New: THorseOAuth2IntrospectConfig;
    function SetHost(AHost: string): THorseOAuth2IntrospectConfig;
    function SetUser(AUser: string): THorseOAuth2IntrospectConfig;
    function SetPath(APath: string): THorseOAuth2IntrospectConfig;
    function SetPassword(APassword: string): THorseOAuth2IntrospectConfig;
    function GetHost(out AHost: string): THorseOAuth2IntrospectConfig;
    function GetUser(out AUser: string): THorseOAuth2IntrospectConfig;
    function GetPassword(out APassword: string): THorseOAuth2IntrospectConfig;
    function GetPath(out APath: string): THorseOAuth2IntrospectConfig;
  end;

  THorseOAuth2IntrospectCallback = class
  private
    FConfig: THorseOAuth2IntrospectConfig;
  public
    constructor Create(AConfig: THorseOAuth2IntrospectConfig);
    destructor Destroy; override;
    class function New(AConfig: THorseOAuth2IntrospectConfig): THorseOAuth2IntrospectCallback;
    function GetConfig(out AConfig: THorseOAuth2IntrospectConfig): THorseOAuth2IntrospectCallback;
    procedure Callback(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: TProc);
  end;

  THorseOAuth2IntrospectManager = class
  private
    FCallbackList: TObjectList<THorseOAuth2IntrospectCallback>;
    class var FDefaultManager: THorseOAuth2IntrospectManager;
    procedure SetCallbackList(const Value: TObjectList<THorseOAuth2IntrospectCallback>);
  protected
    class function GetDefaultManager: THorseOAuth2IntrospectManager; static;
  public
    constructor Create;
    destructor Destroy; override;
    property CallbackList: TObjectList<THorseOAuth2IntrospectCallback> read FCallbackList write SetCallbackList;
    class function HorseCallback(AConfig: THorseOAuth2IntrospectConfig): THorseCallback; overload;
    class destructor UnInitialize;
    class property DefaultManager: THorseOAuth2IntrospectManager read GetDefaultManager;
  end;

implementation

uses
  System.DateUtils,
  System.JSON,
  System.SysUtils,
  System.Classes,
  System.RegularExpressions,
  System.Net.HttpClientComponent,
  System.Net.HttpClient,
  System.Net.URLClient,
  System.NetEncoding;

{ THorseOAuth2IntrospectCallback }

procedure THorseOAuth2IntrospectCallback.Callback(AHorseRequest: THorseRequest; AHorseResponse: THorseResponse; ANext: TProc);
var
  LHTTPClient: TNetHTTPClient;
  LHTTPResponse: IHTTPResponse;
  LEndpoint: string;
  LNetHeaders: TNetHeaders;
  LHost: string;
  LPath: string;
  LUser: string;
  LPassword: string;
  LActive: Boolean;
  LJSONObjectResponse: TJSONObject;
  LJSONObjectSession: TJSONObject;
  LStringList: TStringList;
  LToken: string;
begin
  FConfig
    .GetHost(LHost)
    .GetPath(LPath)
    .GetUser(LUser)
    .GetPassword(LPassword);

  LActive := False;
  LToken := TRegEx.Replace(AHorseRequest.RawWebRequest.Authorization, '^(?:\s+)?bearer\s', '', [TRegExOption.roIgnoreCase]);

  LEndpoint := LHost.TrimRight(['/']) + '/' + LPath.TrimLeft(['/']);
  LHTTPClient := TNetHTTPClient.Create(nil);
  try
    LHTTPClient.SynchronizeEvents := False;

    LNetHeaders := [
      TNameValuePair.Create(
      'Authorization',
      'Basic ' + TNetEncoding.Base64.Encode(LUser + ':' + LPassword))
      ];

    LStringList := TStringList.Create;
    try
      LStringList.AddPair('token', LToken);
      try
        LHTTPResponse := LHTTPClient.POST(LEndpoint, LStringList, nil, TEncoding.UTF8, LNetHeaders);
      except

      end;
    finally
      LStringList.Free;
    end;

    if (LHTTPResponse <> nil) and (LHTTPResponse.StatusCode = 200) then
    begin
      LJSONObjectResponse := TJSONObject.ParseJSONValue(LHTTPResponse.ContentAsString(TEncoding.UTF8)) as TJSONObject;
      try
        if LJSONObjectResponse <> nil then
          LActive := LJSONObjectResponse.GetValue<Boolean>('active');
      finally
        LJSONObjectResponse.Free;
      end;
    end;

  finally
    LHTTPClient.Free;
  end;

  if (LHTTPResponse = nil) or (not LActive) then
  begin
    AHorseResponse.Send('Unauthorized').Status(THTTPStatus.Unauthorized);
    raise EHorseCallbackInterrupted.Create;
  end;

  LJSONObjectSession := TJSONObject.ParseJSONValue(LHTTPResponse.ContentAsString(TEncoding.UTF8)) as TJSONObject;
  try
    AHorseRequest.Session(LJSONObjectSession);
    ANext();
  finally
    LJSONObjectSession.Free;
  end;

end;

constructor THorseOAuth2IntrospectCallback.Create(AConfig: THorseOAuth2IntrospectConfig);
begin
  FConfig := AConfig;
end;

destructor THorseOAuth2IntrospectCallback.Destroy;
begin
  if Assigned(FConfig) then
    FConfig.Free;
  inherited;
end;

function THorseOAuth2IntrospectCallback.GetConfig(out AConfig: THorseOAuth2IntrospectConfig): THorseOAuth2IntrospectCallback;
begin
  Result := Self;
  AConfig := FConfig;
end;

class function THorseOAuth2IntrospectCallback.New(AConfig: THorseOAuth2IntrospectConfig): THorseOAuth2IntrospectCallback;
begin
  Result := THorseOAuth2IntrospectCallback.Create(AConfig);
end;

{ THorseOAuth2IntrospectConfig }

function THorseOAuth2IntrospectConfig.GetHost(out AHost: string): THorseOAuth2IntrospectConfig;
begin
  Result := Self;
  AHost := FHost;
end;

function THorseOAuth2IntrospectConfig.GetPassword(out APassword: string): THorseOAuth2IntrospectConfig;
begin
  Result := Self;
  APassword := FPassword;
end;

function THorseOAuth2IntrospectConfig.GetPath(out APath: string): THorseOAuth2IntrospectConfig;
begin
  Result := Self;
  APath := FPath;
end;

function THorseOAuth2IntrospectConfig.GetUser(out AUser: string): THorseOAuth2IntrospectConfig;
begin
  Result := Self;
  AUser := FUser;
end;

class function THorseOAuth2IntrospectConfig.New: THorseOAuth2IntrospectConfig;
begin
  Result := THorseOAuth2IntrospectConfig.Create;
end;

function THorseOAuth2IntrospectConfig.SetHost(AHost: string): THorseOAuth2IntrospectConfig;
begin
  Result := Self;
  FHost := AHost;
end;

function THorseOAuth2IntrospectConfig.SetPassword(APassword: string): THorseOAuth2IntrospectConfig;
begin
  Result := Self;
  FPassword := APassword;
end;

function THorseOAuth2IntrospectConfig.SetPath(APath: string): THorseOAuth2IntrospectConfig;
begin
  Result := Self;
  FPath := APath;
end;

function THorseOAuth2IntrospectConfig.SetUser(AUser: string): THorseOAuth2IntrospectConfig;
begin
  Result := Self;
  FUser := AUser;
end;

{ THorseOAuth2IntrospectManager }

constructor THorseOAuth2IntrospectManager.Create;
begin
  FCallbackList := TObjectList<THorseOAuth2IntrospectCallback>.Create(True);
end;

destructor THorseOAuth2IntrospectManager.Destroy;
begin
  FCallbackList.Free;
  inherited;
end;

class function THorseOAuth2IntrospectManager.GetDefaultManager: THorseOAuth2IntrospectManager;
begin
  if FDefaultManager = nil then
    FDefaultManager := THorseOAuth2IntrospectManager.Create;
  Result := FDefaultManager;
end;

class function THorseOAuth2IntrospectManager.HorseCallback(AConfig: THorseOAuth2IntrospectConfig): THorseCallback;
var
  LHorseOAuth2IntrospectCallback: THorseOAuth2IntrospectCallback;
begin
  LHorseOAuth2IntrospectCallback := THorseOAuth2IntrospectCallback.Create(AConfig);

  THorseOAuth2IntrospectManager
    .DefaultManager
    .CallbackList
    .Add(LHorseOAuth2IntrospectCallback);

  Result := LHorseOAuth2IntrospectCallback.Callback;
end;

procedure THorseOAuth2IntrospectManager.SetCallbackList(const Value: TObjectList<THorseOAuth2IntrospectCallback>);
begin
  FCallbackList := Value;
end;

class destructor THorseOAuth2IntrospectManager.UnInitialize;
begin
  if FDefaultManager <> nil then
    FreeAndNil(FDefaultManager);
end;

end.
