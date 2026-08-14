# План полного подключения 20 typed providers в OCTOPUS — implementation-ready v6.13

> Этот файл является единственным нормативным migration ledger и архитектурным
> контрактом программы. Если описание PR расходится с общим контрактом выше,
> действует общий контракт; CI обязан отклонять такое расхождение до merge.

## 1. Цель и границы

Подключить следующие 20 action identities как рабочие typed providers:

```text
Pivot:
- pivot_remote_forward
- pivot_ssh_chain
- pivot_proxy_scan

Kerberos:
- kerberos_extract_tickets
- kerberos_crack_tickets

AD credential access:
- ad_pass_the_ticket
- pass_the_hash
- ad_dump_lsass
- ad_sam_dump

AD remote execution:
- ad_smbexec
- ad_winrm_exec
- ad_dcom_exec
- ad_remote_execution

C2:
- dns_c2_channel
- c2_enroll
- c2_deploy
- c2_channel_create
- c2_task
- c2_cleanup

Payload:
- payload_keying
```

Это 20 action identities, но не 20 независимых leaf implementations:

```text
ad_remote_execution → composite selector
c2_channel_create   → composite transport router
остальные           → concrete typed providers
```

Каноническую execution classification задают два независимых поля:

```text
ExecutionNodeKind.LEAF + ProviderTransport.IN_PROCESS:
- payload_keying
- kerberos_extract_tickets
- kerberos_crack_tickets
- ad_pass_the_ticket
- pass_the_hash
- ad_dump_lsass
- ad_sam_dump
- ad_smbexec
- ad_winrm_exec
- ad_dcom_exec
- pivot_remote_forward
- pivot_ssh_chain
- pivot_proxy_scan
- c2_deploy
- c2_cleanup

ExecutionNodeKind.LEAF + ProviderTransport.LOCAL_DAEMON_IPC:
- dns_c2_channel
- c2_enroll
- c2_task

ExecutionNodeKind.COMPOSITE_ROUTER + ProviderTransport.CHILD_EXECUTOR:
- ad_remote_execution
- c2_channel_create
```

Отдельный surface enum не вводить. Legacy/raw command facade не является provider transport и управляется отдельно через `ToolDef.enabled` и `raw_command_supported`.

Финальное статическое состояние всех identities:

```text
configured=true
mounted=true
typed_action_supported=true
manual_gate=true
raw_command_supported=false
```

Финальное динамическое состояние в reference runtime:

```text
available=true
```

Исполнимость никогда не хранить как доверенный флаг:

```text
executable =
    configured
    && mounted
    && available
    && authorized
```

Где:

```text
configured ← canonical ProviderMountRegistry
mounted    ← canonical ProviderMountRegistry
available  ← dynamic ProviderReadinessProbe
authorized ← request-scoped ActionExecutor + ExecutionPolicy decision
```

Итоговая цель:

```text
20/20 configured
20/20 mounted
20/20 typed interfaces
20/20 concrete или composite production wiring
20/20 available в reference runtime
0 provider_not_configured
0 unconfigured typed providers
0 production NullProvider
0 production FakeProvider
```

## 1.1. Подтверждённые migration constraints текущего репозитория

План обязан мигрировать существующие production paths, а не только добавить параллельные V2 abstractions:

```text
- текущий Go agent получает tasks как map с полем command и запускает OS process;
- текущий Python agent использует тот же raw-command task contract;
- current builder принимает enrollment_token и самостоятельно выпускает token при пустом значении;
- current GET_RESULTS удаляет task rows после чтения;
- systemd unit использует DynamicUser=yes;
- core/tools/manual_actions.py отсутствует и должен быть создан;
- scripts/quality/mypy_gate.py отсутствует и должен быть создан;
- quality/mypy-import-aware.ini существует и уже вызывается из CI;
- `LegacyActionDescriptorV1.provider` и `LegacyActionDescriptorV1.provider_mounted` читаются V1 runtime/test consumers; V2/shared consumers требуют отдельной migration ledger.
```

Ни один старый path не может остаться вторым production route после соответствующего migration PR.

---

## 2. Единственные владельцы canonical state

### 2.1. Action semantics


Существующие 96 adapters и новые 20 typed identities используют разные versioned descriptor contracts. Их нельзя сводить к одному `ActionDescriptor`, пока V1 lifecycle остаётся production-supported.

```python
# V1 is the existing class from core/actions/models.py. Do not re-declare its
# constructor: field order, defaults and all 96 call sites remain unchanged.
LegacyActionDescriptorV1: TypeAlias = ActionDescriptor

# Owner: core/actions/adapter_registration.py (PR-1). This is an alias to the
# existing class from core/actions/base.py, not a replacement class.
ActionAdapterV1: TypeAlias = ActionAdapter


class CheckPolicyV2(str, Enum):
    REQUIRED = "required"
    NOT_SUPPORTED = "not_supported"


class VerifyPolicyV2(str, Enum):
    REQUIRED = "required"
    NOT_SUPPORTED = "not_supported"


@dataclass(frozen=True)
class ActionDescriptorV2:
    schema_version: Literal["2.0"]
    action_id: str
    name: str
    aliases: tuple[str, ...]
    input_schema_id: str
    result_schema_id: str
    kind: ActionKind
    execution_node_kind: ExecutionNodeKind
    capability_class: str
    risk_class: str
    required_fact_type_ids: tuple[str, ...]
    killchain_stage: str | None
    manual_gate: bool
    check_policy: CheckPolicyV2
    verify_policy: VerifyPolicyV2


ActionDescriptorUnion: TypeAlias = LegacyActionDescriptorV1 | ActionDescriptorV2


@runtime_checkable
class TypedActionAdapterRegistrationV2(Protocol):
    """PR-1 structural header only; execution methods are added in PR-7."""

    adapter_api_version: Literal[2]
    descriptor: ActionDescriptorV2
```

`LegacyActionDescriptorV1` сохраняет существующий default
`schema_version=ACTION_DESCRIPTOR_SCHEMA_VERSION`; v6.13 не превращает его в
обязательный constructor argument.

PR-1 не импортирует ещё не созданные `V2InputUnion` или `ExecutionResultV2`.
`input_schema_id` и `result_schema_id` являются стабильными строковыми IDs.
PR-6 связывает `input_schema_id` с exact decoder/DTO. PR-7 связывает
`result_schema_id` с closed provider/execution result registry.

На время migration существующий класс/import-name `ActionDescriptor` остаётся неизменным V1 contract; `LegacyActionDescriptorV1` является только его type alias. Только новые V2 adapter construction sites используют `ActionDescriptorV2`.

`ActionDescriptorV2` является единственным immutable runtime projection и API
surface для V2 action semantics:

```text
action_id
name
aliases
input_schema_id
result_schema_id
kind                     # существующий V1 ActionKind
execution_node_kind      # новый graph/runtime classification
capability_class
risk_class
required_fact_type_ids
killchain_stage
manual_gate
check_policy
verify_policy
```

Существующий enum `ActionKind` с V1-видами:

```text
REGISTERED_TOOL
EXPLOIT
METASPLOIT
PLUGIN
KILLCHAIN
```

не переименовывать и не переиспользовать для leaf/router classification.

Добавить отдельный enum:

```python
class ExecutionNodeKind(str, Enum):
    LEAF = "leaf"
    COMPOSITE_ROUTER = "composite_router"
```

`LegacyActionDescriptorV1.kind: ActionKind` сохраняет текущую V1 семантику.
`V2ActionSemanticBinding.execution_node_kind` — declarative source leaf/router
semantics, а `ActionDescriptorV2.execution_node_kind` — его единственная
immutable runtime projection.

`required_fact_type_ids` содержит только IDs trusted-fact predicates. Наличие
credential/session/ticket/artifact/route/agent/channel references проверяется
exact input decoder, reference checkout и deep policy, а не строкой в descriptor.
Неизвестный fact type ID делает V2 catalog invalid. `aliases` разрешаются в
canonical `action_id` до V2 dispatch; единственный alias этой программы —
`pass_the_hash -> ("pth",)`. Коллизии aliases/names/action IDs между V1 и V2
запрещены.

`ActionDescriptorV2` не содержит:

```text
provider
provider_owner
provider_mounted
configured
mounted
available
provider_transport
execution_mode
```

`LegacyActionDescriptorV1.provider` и `LegacyActionDescriptorV1.provider_mounted` продолжают обслуживать только 96 V1 adapters. Они не могут участвовать в V2 canonical state, V2 policy, V2 readiness или V2 doctor output.

Schema-versioned migration из serialized V1 descriptor в V2 обязана отбросить legacy owner/mount fields и заново разрешить wiring по `action_id`.

### 2.2. Provider wiring

`ProviderMountSpec` является единственным владельцем wiring только для V2 identities:

```python
@dataclass(frozen=True)
class ProviderMountSpec:
    schema_version: str
    action_id: str
    adapter_class: str
    adapter_api_version: Literal[2]
    provider_owner: str
    provider_transport: ProviderTransport
    execution_mode: ProviderExecutionModeV2
    readiness_probe_id: str

    configured: bool
    mounted: bool
    typed_action_supported: bool
    raw_command_supported: bool


@dataclass(frozen=True)
class ProviderMountSnapshotV2:
    spec: ProviderMountSpec
    revision: int
    mount_digest: str


def canonical_provider_mount_snapshot_digest(
    snapshot: ProviderMountSnapshotV2,
) -> str:
    """Tagged canonical digest of every spec field plus revision, excluding mount_digest."""
    ...


@runtime_checkable
class ProviderMountRegistry(Protocol):
    def require_v2(self, action_id: str) -> ProviderMountSnapshotV2: ...
    def assert_current(self, snapshot: ProviderMountSnapshotV2) -> None: ...
    def snapshots(self) -> tuple[ProviderMountSnapshotV2, ...]: ...


class ProviderTransport(str, Enum):
    IN_PROCESS = "in_process"
    LOCAL_DAEMON_IPC = "local_daemon_ipc"
    CHILD_EXECUTOR = "child_executor"


class ProviderExecutionModeV2(str, Enum):
    COOPERATIVE_IN_PROCESS = "cooperative_in_process"
    DEADLINE_LOCAL_IPC = "deadline_local_ipc"
    CHILD_EXECUTOR = "child_executor"
```

`ProviderMountRegistry` содержит ровно 20 entries — только identities с `adapter_api_version=2`. Он обязан отклонять lookup 96 V1 action IDs и не является источником provider wiring для V1.

`ProviderMountSpec` не содержит:

```text
action_name
input_schema_id
result_schema_id
kind
execution_node_kind
manual_gate
capability_class
risk_class
killchain_stage
required_fact_type_ids
available
authorized
executable
```

Catalog boundary является tagged union:

```python
@dataclass(frozen=True)
class LegacyActionCatalogEntry:
    descriptor: LegacyActionDescriptorV1
    adapter: ActionAdapterV1
    adapter_api_version: Literal[1] = 1


@dataclass(frozen=True)
class TypedActionCatalogEntry:
    descriptor: ActionDescriptorV2
    mount: ProviderMountSnapshotV2
    adapter: TypedActionAdapterRegistrationV2
    adapter_api_version: Literal[2] = 2


ActionCatalogEntry = LegacyActionCatalogEntry | TypedActionCatalogEntry
```

`ActionCatalog.resolve_entry(action_id)` возвращает `ActionCatalogEntry`, а consumers обязаны исчерпывающе обработать обе variants:

```text
LegacyActionCatalogEntry:
    provider owner/mount читаются из LegacyActionDescriptorV1
    ProviderMountRegistry не вызывается

TypedActionCatalogEntry:
    semantics читаются из ActionDescriptorV2
    wiring читается из ProviderMountRegistry.require_v2(action_id).spec
```

UI/doctor:

```text
V1 → читает существующие descriptor fields через V1 compatibility presenter
V2 → join ActionDescriptorV2 + ProviderMountSnapshotV2.spec только по action_id
```

Ни один общий consumer не должен без version/tag check заменять `descriptor.provider` на `mount_registry.require(...)`.

### 2.3. Mapping

```text
ad_remote_execution:
    execution_node_kind=COMPOSITE_ROUTER
    provider_transport=CHILD_EXECUTOR

c2_channel_create:
    execution_node_kind=COMPOSITE_ROUTER
    provider_transport=CHILD_EXECUTOR

dns_c2_channel, c2_enroll, c2_task:
    execution_node_kind=LEAF
    provider_transport=LOCAL_DAEMON_IPC

остальные identities:
    execution_node_kind=LEAF
    provider_transport=IN_PROCESS
```

`REGISTERED_COMMAND` не является provider transport. Это отдельный legacy/raw facade, контролируемый `ToolDef.enabled` и `raw_command_supported`.

PR-1 обязан инвентаризировать оба живых legacy-поля:

```text
LegacyActionDescriptorV1.provider
LegacyActionDescriptorV1.provider_mounted
```

Их нельзя глобально переносить в 20-entry `ProviderMountRegistry`. Они остаются разрешены только в reviewed V1 compatibility path. В V2/shared runtime их использование запрещается AST ratchet.

### 2.4. Canonical schema-ID matrix для 20 V2 identities

Gemini не выбирает и не генерирует schema IDs. Единственный владелец строковых
bindings — `core/actions/schema_bindings.py`, создаваемый в PR-1:

```python
@dataclass(frozen=True)
class V2ActionSchemaBinding:
    action_id: str
    input_schema_id: str
    result_schema_id: str
```

PR-1 хранит только три стабильных строковых ID. Он не импортирует DTO из PR-6
или provider-result classes из PR-7. Следующая таблица нормативна целиком:

| Identity | Canonical `action_id` | Exact `input_schema_id` | PR-6 input DTO | Exact `result_schema_id` | PR-7 result contract |
|---|---|---|---|---|---|
| `payload_keying` | `plugin:payload_keying` | `octopus:input:payload_keying:2.0` | `PayloadKeyingInputV2` | `octopus:result:payload_keying:2.0` | `ArtifactProviderResult` |
| `kerberos_extract_tickets` | `killchain:kerberos_extract_tickets` | `octopus:input:kerberos_extract_tickets:2.0` | `KerberosExtractInputV2` | `octopus:result:kerberos_extract_tickets:2.0` | `ArtifactProviderResult` |
| `kerberos_crack_tickets` | `killchain:kerberos_crack_tickets` | `octopus:input:kerberos_crack_tickets:2.0` | `KerberosCrackInputV2` | `octopus:result:kerberos_crack_tickets:2.0` | `CredentialProviderResult` |
| `ad_pass_the_ticket` | `killchain:ad_pass_the_ticket` | `octopus:input:ad_pass_the_ticket:2.0` | `PassTheTicketInputV2` | `octopus:result:ad_pass_the_ticket:2.0` | `RemoteAuthProviderResultV2` |
| `pass_the_hash` | `killchain:pass_the_hash` | `octopus:input:pass_the_hash:2.0` | `PassTheHashInputV2` | `octopus:result:pass_the_hash:2.0` | `RemoteAuthProviderResultV2` |
| `ad_dump_lsass` | `killchain:ad_dump_lsass` | `octopus:input:ad_dump_lsass:2.0` | `CredentialDumpInputV2` | `octopus:result:ad_dump_lsass:2.0` | `SensitiveProviderResult` |
| `ad_sam_dump` | `killchain:ad_sam_dump` | `octopus:input:ad_sam_dump:2.0` | `CredentialDumpInputV2` | `octopus:result:ad_sam_dump:2.0` | `SensitiveProviderResult` |
| `ad_smbexec` | `killchain:ad_smbexec` | `octopus:input:ad_smbexec:2.0` | `RemoteExecInputV2` | `octopus:result:ad_smbexec:2.0` | `OperationProviderResult` |
| `ad_winrm_exec` | `killchain:ad_winrm_exec` | `octopus:input:ad_winrm_exec:2.0` | `RemoteExecInputV2` | `octopus:result:ad_winrm_exec:2.0` | `OperationProviderResult` |
| `ad_dcom_exec` | `killchain:ad_dcom_exec` | `octopus:input:ad_dcom_exec:2.0` | `RemoteExecInputV2` | `octopus:result:ad_dcom_exec:2.0` | `OperationProviderResult` |
| `ad_remote_execution` | `killchain:ad_remote_execution` | `octopus:input:ad_remote_execution:2.0` | `RemoteExecInputV2` | `octopus:result:ad_remote_execution:2.0` | `CompositeProviderResult` |
| `pivot_remote_forward` | `killchain:pivot_remote_forward` | `octopus:input:pivot_remote_forward:2.0` | `RemoteForwardInputV2` | `octopus:result:pivot_remote_forward:2.0` | `RouteProviderResult` |
| `pivot_ssh_chain` | `killchain:pivot_ssh_chain` | `octopus:input:pivot_ssh_chain:2.0` | `SSHChainInputV2` | `octopus:result:pivot_ssh_chain:2.0` | `SessionProviderResult` |
| `pivot_proxy_scan` | `killchain:pivot_proxy_scan` | `octopus:input:pivot_proxy_scan:2.0` | `PivotProxyScanInputV2` | `octopus:result:pivot_proxy_scan:2.0` | `OperationProviderResult` |
| `dns_c2_channel` | `c2:dns_c2_channel` | `octopus:input:dns_c2_channel:2.0` | `DNSC2ChannelInputV2` | `octopus:result:dns_c2_channel:2.0` | `C2ProviderResult` |
| `c2_enroll` | `c2:c2_enroll` | `octopus:input:c2_enroll:2.0` | `C2EnrollmentIssueInput` | `octopus:result:c2_enroll:2.0` | `C2ProviderResult` |
| `c2_deploy` | `c2:c2_deploy` | `octopus:input:c2_deploy:3.0` | `C2DeployInputV3` | `octopus:result:c2_deploy:2.0` | `C2ProviderResult` |
| `c2_channel_create` | `c2:c2_channel_create` | `octopus:input:c2_channel_create:2.0` | `C2ChannelCreateInputV2` | `octopus:result:c2_channel_create:2.0` | `CompositeProviderResult` |
| `c2_task` | `c2:c2_task` | `octopus:input:c2_task:2.0` | `C2TaskInputV2` | `octopus:result:c2_task:2.0` | `C2ProviderResult` |
| `c2_cleanup` | `c2:c2_cleanup` | `octopus:input:c2_cleanup:2.0` | `C2CleanupInputV2` | `octopus:result:c2_cleanup:2.0` | `OperationProviderResult` |

Rules:

```text
- action_id/input_schema_id/result_schema_id are immutable after PR-1;
- descriptor construction reads all three IDs from this matrix;
- PR-6 must bind every input schema ID to the exact DTO shown above;
- PR-7 must bind every result schema ID to the exact result contract shown above;
- a shared DTO does not imply a shared schema ID;
- unknown, duplicate or mismatched bindings fail catalog construction;
- changing an ID requires a new schema version, migration decoder and compatibility test.
```


### 2.5. Canonical semantic matrix для 20 V2 identities

`core/actions/semantic_bindings.py` (PR-1) является единственным declarative
source of truth для значений security/execution semantics. Он содержит только
enum/string IDs и потому не
зависит от PR-6/PR-7 DTO:

```python
@dataclass(frozen=True)
class V2ActionSemanticBinding:
    action_id: str
    name: str
    aliases: tuple[str, ...]
    kind: ActionKind
    execution_node_kind: ExecutionNodeKind
    capability_class: str
    risk_class: str
    required_fact_type_ids: tuple[str, ...]
    killchain_stage: str
    manual_gate: Literal[True]
    check_policy: Literal[CheckPolicyV2.REQUIRED]
    verify_policy: Literal[VerifyPolicyV2.REQUIRED]
```

Следующая таблица нормативна. Пустое значение означает `()`; все строки имеют
`manual_gate=True`, `check_policy=REQUIRED`, `verify_policy=REQUIRED`.

| Identity | `ActionKind` | Node | Capability | Risk | Required trusted fact type IDs | Stage | Aliases |
|---|---|---|---|---|---|---|---|
| `payload_keying` | `PLUGIN` | `LEAF` | `evasion` | `high` | — | `weaponization` | — |
| `kerberos_extract_tickets` | `KILLCHAIN` | `LEAF` | `credential_extraction` | `high` | `confirmed_windows_access`, `ad_environment_detected` | `credential_access` | — |
| `kerberos_crack_tickets` | `KILLCHAIN` | `LEAF` | `credential_extraction` | `high` | — | `credential_access` | — |
| `ad_pass_the_ticket` | `KILLCHAIN` | `LEAF` | `lateral_movement` | `critical` | `confirmed_ad_access` | `lateral_movement` | — |
| `pass_the_hash` | `KILLCHAIN` | `LEAF` | `lateral_movement` | `critical` | `confirmed_ad_access` | `lateral_movement` | `pth` |
| `ad_dump_lsass` | `KILLCHAIN` | `LEAF` | `credential_extraction` | `critical` | `confirmed_windows_access` | `credential_access` | — |
| `ad_sam_dump` | `KILLCHAIN` | `LEAF` | `credential_extraction` | `critical` | `confirmed_windows_access` | `credential_access` | — |
| `ad_smbexec` | `KILLCHAIN` | `LEAF` | `lateral_movement` | `critical` | `confirmed_ad_access`, `smb_service_available` | `lateral_movement` | — |
| `ad_winrm_exec` | `KILLCHAIN` | `LEAF` | `lateral_movement` | `critical` | `confirmed_ad_access`, `winrm_service_available` | `lateral_movement` | — |
| `ad_dcom_exec` | `KILLCHAIN` | `LEAF` | `lateral_movement` | `critical` | `confirmed_ad_access`, `dcom_service_available` | `lateral_movement` | — |
| `ad_remote_execution` | `KILLCHAIN` | `COMPOSITE_ROUTER` | `lateral_movement` | `critical` | `confirmed_ad_access` | `lateral_movement` | — |
| `pivot_remote_forward` | `KILLCHAIN` | `LEAF` | `pivot` | `high` | `confirmed_ssh_access` | `lateral_movement` | — |
| `pivot_ssh_chain` | `KILLCHAIN` | `LEAF` | `pivot` | `high` | `confirmed_ssh_access` | `lateral_movement` | — |
| `pivot_proxy_scan` | `KILLCHAIN` | `LEAF` | `pivot` | `medium` | `confirmed_pivot` | `lateral_movement` | — |
| `dns_c2_channel` | `KILLCHAIN` | `LEAF` | `c2` | `critical` | `approved_c2_scope` | `command_and_control` | — |
| `c2_enroll` | `KILLCHAIN` | `LEAF` | `c2` | `critical` | `approved_c2_scope` | `command_and_control` | — |
| `c2_deploy` | `KILLCHAIN` | `LEAF` | `c2` | `critical` | `confirmed_target_access`, `c2_channel_authorized` | `command_and_control` | — |
| `c2_channel_create` | `KILLCHAIN` | `COMPOSITE_ROUTER` | `c2` | `critical` | `approved_c2_scope` | `command_and_control` | — |
| `c2_task` | `KILLCHAIN` | `LEAF` | `c2` | `high` | `c2_agent_enrolled` | `command_and_control` | — |
| `c2_cleanup` | `KILLCHAIN` | `LEAF` | `c2` | `medium` | — | `command_and_control` | — |

Descriptor construction выполняет exact join schema matrix §2.4 + semantic
matrix §2.5 по `action_id`; `ActionDescriptorV2` хранит полученную immutable
runtime projection, но не является вторым declarative source. Вручную
дублировать значения в adapters/config нельзя.
`ActionPreconditionRegistryV2` (PR-4) связывает каждый
`required_fact_type_id` с exact `TrustedFactType`; unknown/duplicate IDs,
неполный join и любое отличие descriptor от матриц делают catalog invalid.
Reference existence (`c2_cleanup` resource, session, route, ticket, agent и т.д.)
остаётся в closed input/reference policy и не маскируется fact ID.

```python
class PreconditionCardinalityV2(str, Enum):
    AT_LEAST_ONE = "at_least_one"
    EACH_MATCHING_TARGET = "each_matching_target"


@dataclass(frozen=True)
class ActionPreconditionBindingV2:
    required_fact_type_id: str
    fact_type: TrustedFactType
    predicate_id: str
    target_role: TargetRole | None
    cardinality: PreconditionCardinalityV2
    binding_digest: str


@dataclass(frozen=True)
class PreconditionDecisionV2:
    satisfied: bool
    matched_fact_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    decision_digest: str


@runtime_checkable
class ActionPreconditionRegistryV2(Protocol):
    def require_binding(
        self,
        required_fact_type_id: str,
    ) -> ActionPreconditionBindingV2: ...

    def evaluate(
        self,
        *,
        binding: ActionPreconditionBindingV2,
        facts: tuple[TrustedFactSnapshot, ...],
        targets: tuple[ExtractedActionTarget, ...],
        mission_id: str,
        now: float,
    ) -> PreconditionDecisionV2: ...
```

The executor resolves these bindings, never an adapter/provider. Evaluation
requires exact fact type, target/mission binding, trusted VERIFIED state,
current revision/digest and fresh/complete coverage. `UNKNOWN`, stale,
contradicted, degraded, wrong-cardinality or unrecognized predicate state deny;
all matched fact refs/digests enter the decision trace.

`V2ActionSemanticBinding` является declarative source обязательности V2 phases;
`ActionDescriptorV2` является единственной runtime projection этих значений.
Gemini не выводит policy из наличия метода.

Semantics:

```text
check_bound:
    side-effect-free validation of provider-specific request feasibility;
    runs after deep authorization and snapshot checkout, before attempt reservation;
    receives no secret/live material and no write/staging capability;
    failure consumes zero approval uses.

verify_bound:
    validates the normalized provider result and any already-created draft
    descriptors before publication;
    receives no staging/participant-registration capability and cannot create,
    mutate or publish resources;
    it is result-integrity verification, not independent vulnerability proof.
```

A fully mounted descriptor with `REQUIRED` phase and an adapter without the
matching protocol fails catalog construction. До PR-7 PR-1 выполняет только
structural validation незамонтированных V2 registrations; full method validation
включается атомарно в PR-7 до первого `mounted=true`. Runtime introspection не
меняет policy. `NOT_SUPPORTED` недопустим для этих 20 identities.

## 4. Executor-resolved ingress, principal, mission, approval и two-phase authorization

Public V2 ingress принимает serialized payload, но никогда не принимает готовый
ActionRequestV2 или caller-created typed dataclass напрямую.

Phase 1 — bounded envelope decoding:

ActionRequestV2EnvelopeDecoder:
- проверяет exact top-level schema;
- ограничивает размер, глубину, длину строк и количество элементов;
- отклоняет unknown fields;
- отклоняет ingress/principal/role/approved/session authority;
- сохраняет typed_input payload только как private decoder value.

Разрешённые caller fields:

request_id
mission_ref
approval_ref
precondition_fact_refs
idempotency_key
typed_input

parent_execution_id, execution_graph_id, ingress lease, principal и execution
budget не являются caller fields.

### 4.0. PR-safe staged V2 request и execution-result foundation

PR-2 must type-check before the 20 exact input DTOs and provider-result union
exist. It therefore owns only bounded envelope models and final publication
foundation types. `V2InputUnion` and canonical `ActionRequestV2` are created in
PR-6; `ProviderResult` variants are created in PR-7.

```python
ACTION_REQUEST_V2_ENVELOPE_SCHEMA_VERSION: Final = "2.0"


@dataclass(frozen=True, repr=False)
class BoundedTypedInputPayloadV2:
    schema_id: str
    canonical_json: bytes = field(repr=False, compare=False)
    byte_length: int
    sha256_digest: str


@dataclass(frozen=True, repr=False)
class BoundedActionRequestV2Envelope:
    request_id: str
    mission_ref: str
    approval_ref: str | None
    precondition_fact_refs: tuple[str, ...]
    idempotency_key: str | None
    typed_input_payload: BoundedTypedInputPayloadV2
    schema_version: Literal["2.0"] = field(
        default=ACTION_REQUEST_V2_ENVELOPE_SCHEMA_VERSION,
        init=False,
    )
```

PR-2 creates a fail-closed `TypedInputDecoderRegistry` skeleton. Until PR-6
registers all 20 `(action_id, input_schema_id)` decoders, it exposes only:

```python
class TypedInputDecoderNotRegistered(RuntimeError):
    def __init__(self, action_id: str, input_schema_id: str) -> None: ...


class TypedInputDecoderRegistry:
    def require_decoder(self, action_id: str, input_schema_id: str) -> NoReturn:
        raise TypedInputDecoderNotRegistered(action_id, input_schema_id)
```

PR-2 also owns stable report/result references so its executor signatures do not
import PR-7 classes:

```python
class ExecutionStatusV2(str, Enum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    BLOCKED = "blocked"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    INTERNAL_FAILURE = "internal_failure"


class CleanupStatusV2(str, Enum):
    NOT_REQUIRED = "not_required"
    SUCCEEDED = "succeeded"
    FAILED = "failed"


@dataclass(frozen=True)
class CleanupErrorSummaryV2:
    phase: str
    reason_code: str


@dataclass(frozen=True)
class CleanupSummaryV2:
    status: CleanupStatusV2
    errors: tuple[CleanupErrorSummaryV2, ...] = ()

    def __post_init__(self) -> None:
        if self.status in (CleanupStatusV2.NOT_REQUIRED, CleanupStatusV2.SUCCEEDED):
            if self.errors:
                raise ValueError("cleanup_success_has_errors")
        elif not self.errors:
            raise ValueError("cleanup_failure_requires_error")


def derive_effective_status_and_reasons(
    transaction_status: ExecutionStatusV2,
    cleanup: CleanupSummaryV2,
    reason_codes: tuple[str, ...],
) -> tuple[ExecutionStatusV2, tuple[str, ...]]: ...


@dataclass(frozen=True)
class ExecutionResultV2:
    schema_version: Literal["2.0"]
    execution_id: str
    action_id: str
    status: Literal[ExecutionStatusV2.SUCCEEDED, ExecutionStatusV2.PARTIAL]
    reason_codes: tuple[str, ...]
    artifact_refs: tuple[str, ...]
    credential_refs: tuple[str, ...]
    session_refs: tuple[str, ...]
    route_refs: tuple[str, ...]
    c2_refs: tuple[str, ...]
    fact_refs: tuple[str, ...]
    audit_ref: str
    decision_trace_ref: str
    linked_result_refs: tuple[ExecutionResultRefV2, ...]
    provenance_chain: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionResultDraftRefV2:
    transaction_id: str
    draft_id: str
    execution_id: str
    action_id: str
    normalized_draft_digest: str


@dataclass(frozen=True)
class ExecutionResultRefV2:
    reference: str
    revision: int
    execution_id: str
    action_id: str
    result_digest: str


class _CommittedBindingConstructionTokenV2:
    pass


@dataclass(frozen=True, init=False)
class CommittedExecutionResultBindingV2:
    """Store-issued only after the coordinator reaches global COMMITTED."""

    transaction_id: str
    coordinator_revision: int
    commit_state: Literal["committed"]
    execution_result_ref: ExecutionResultRefV2
    canonical_result_digest: str
    committed_marker_ref: str
    committed_marker_digest: str

    @classmethod
    def _from_committed_marker(
        cls,
        *,
        token: _CommittedBindingConstructionTokenV2,
        transaction_id: str,
        coordinator_revision: int,
        execution_result_ref: ExecutionResultRefV2,
        canonical_result_digest: str,
        committed_marker_ref: str,
        committed_marker_digest: str,
    ) -> CommittedExecutionResultBindingV2: ...


def canonical_execution_result_digest(result: ExecutionResultV2) -> str:
    """SHA-256 over canonical JSON schema execution-result/2.0."""
    ...


class _FinalizationConstructionTokenV2:
    pass


@dataclass(frozen=True, init=False)
class InvocationFinalizationRecordV2:
    schema_version: Literal["1.0"]
    execution_id: str
    action_id: str
    transaction_id: str
    transaction_status: ExecutionStatusV2
    effective_status: ExecutionStatusV2
    cleanup: CleanupSummaryV2
    transaction_reason_codes: tuple[str, ...]
    effective_reason_codes: tuple[str, ...]
    finalized_at: float

    @classmethod
    def _from_factory(
        cls,
        *,
        _token: _FinalizationConstructionTokenV2,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        transaction_status: ExecutionStatusV2,
        effective_status: ExecutionStatusV2,
        cleanup: CleanupSummaryV2,
        transaction_reason_codes: tuple[str, ...],
        effective_reason_codes: tuple[str, ...],
        finalized_at: float,
    ) -> InvocationFinalizationRecordV2: ...


class InvocationFinalizationFactoryV2:
    _construction_token: _FinalizationConstructionTokenV2

    def create(
        self,
        *,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        transaction_status: ExecutionStatusV2,
        cleanup: CleanupSummaryV2,
        transaction_reason_codes: tuple[str, ...],
        finalized_at: float,
    ) -> InvocationFinalizationRecordV2: ...


@dataclass(frozen=True)
class InvocationFinalizationRefV2:
    reference: str
    revision: int
    execution_id: str
    action_id: str
    transaction_id: str
    finalization_digest: str


@dataclass(frozen=True)
class InvocationFinalizationRetryRefV2:
    reference: str
    revision: int
    execution_id: str
    action_id: str
    transaction_id: str
    finalization_digest: str


def canonical_invocation_finalization_digest(
    record: InvocationFinalizationRecordV2,
) -> str:
    """RFC-8785 digest tagged invocation-finalization/1.0."""
    ...


@dataclass(frozen=True)
class ActionExecutionReportV2:
    schema_version: Literal["2.0"]
    execution_id: str
    action_id: str
    transaction_id: str
    execution_result: ExecutionResultV2 | None
    execution_result_ref: ExecutionResultRefV2 | None
    committed_result_binding: CommittedExecutionResultBindingV2 | None
    finalization: InvocationFinalizationRecordV2
    finalization_ref: InvocationFinalizationRefV2 | None
    finalization_retry_ref: InvocationFinalizationRetryRefV2 | None
    finalization_persistence_pending: bool

    def __post_init__(self) -> None:
        committed_parts = (
            self.execution_result,
            self.execution_result_ref,
            self.committed_result_binding,
        )
        if any(part is None for part in committed_parts) and any(part is not None for part in committed_parts):
            raise ValueError("committed_result_all_or_none")
        commit_status = self.finalization.transaction_status in (
            ExecutionStatusV2.SUCCEEDED,
            ExecutionStatusV2.PARTIAL,
        )
        if commit_status != all(part is not None for part in committed_parts):
            raise ValueError("publication_table_mismatch")
        if self.finalization_persistence_pending:
            if self.finalization_ref is not None or self.finalization_retry_ref is None:
                raise ValueError("finalization_pending_xor")
        elif self.finalization_ref is None or self.finalization_retry_ref is not None:
            raise ValueError("finalization_persisted_xor")
        if (
            self.finalization.execution_id != self.execution_id
            or self.finalization.action_id != self.action_id
            or self.finalization.transaction_id != self.transaction_id
        ):
            raise ValueError("finalization_identity")
        if self.execution_result is not None and (self.finalization.transaction_status != self.execution_result.status):
            raise ValueError("transaction_status_mismatch")
        if self.execution_result is not None:
            assert self.execution_result_ref is not None
            assert self.committed_result_binding is not None
            result_digest = canonical_execution_result_digest(self.execution_result)
            if (
                self.execution_result.execution_id != self.execution_id
                or self.execution_result.action_id != self.action_id
                or self.execution_result_ref.execution_id != self.execution_id
                or self.execution_result_ref.action_id != self.action_id
                or self.execution_result_ref.result_digest != result_digest
                or self.committed_result_binding.transaction_id != self.transaction_id
                or self.committed_result_binding.commit_state != "committed"
                or self.committed_result_binding.execution_result_ref != self.execution_result_ref
                or self.committed_result_binding.canonical_result_digest != result_digest
            ):
                raise ValueError("committed_result_binding_mismatch")
        expected_effective, expected_reasons = derive_effective_status_and_reasons(
            self.finalization.transaction_status,
            self.finalization.cleanup,
            self.finalization.transaction_reason_codes,
        )
        if (
            self.finalization.effective_status != expected_effective
            or self.finalization.effective_reason_codes != expected_reasons
        ):
            raise ValueError("finalization_precedence_mismatch")
        if self.finalization_ref is not None and (
            self.finalization_ref.execution_id != self.execution_id
            or self.finalization_ref.action_id != self.action_id
            or self.finalization_ref.transaction_id != self.transaction_id
            or self.finalization_ref.finalization_digest != canonical_invocation_finalization_digest(self.finalization)
        ):
            raise ValueError("finalization_ref_mismatch")
        if self.finalization_retry_ref is not None and (
            self.finalization_retry_ref.execution_id != self.execution_id
            or self.finalization_retry_ref.action_id != self.action_id
            or self.finalization_retry_ref.transaction_id != self.transaction_id
            or self.finalization_retry_ref.finalization_digest
            != canonical_invocation_finalization_digest(self.finalization)
        ):
            raise ValueError("finalization_retry_ref_mismatch")

    def require_successful_committed_result_ref(self) -> ExecutionResultRefV2:
        if (
            self.execution_result_ref is None
            or self.execution_result is None
            or self.committed_result_binding is None
            or self.execution_result.status not in (ExecutionStatusV2.SUCCEEDED, ExecutionStatusV2.PARTIAL)
            or self.finalization.effective_status not in (ExecutionStatusV2.SUCCEEDED, ExecutionStatusV2.PARTIAL)
        ):
            raise ChildExecutionHasNoCommittedResult(self.execution_id)
        result_digest = canonical_execution_result_digest(self.execution_result)
        binding = self.committed_result_binding
        if (
            self.execution_result.execution_id != self.execution_id
            or self.execution_result.action_id != self.action_id
            or self.execution_result_ref.execution_id != self.execution_id
            or self.execution_result_ref.action_id != self.action_id
            or binding.transaction_id != self.transaction_id
            or binding.commit_state != "committed"
            or binding.execution_result_ref != self.execution_result_ref
            or binding.canonical_result_digest != result_digest
            or self.execution_result_ref.result_digest != result_digest
            or self.finalization.execution_id != self.execution_id
            or self.finalization.action_id != self.action_id
            or self.finalization.transaction_id != self.transaction_id
        ):
            raise ChildExecutionHasNoCommittedResult(self.execution_id)
        return self.execution_result_ref


class ChildExecutionHasNoCommittedResult(RuntimeError):
    """The child has no successful globally committed result reference."""


class ExecutionProgressStatusV2(str, Enum):
    TERMINATION_PENDING = "termination_pending"
    RECONCILIATION_PENDING = "reconciliation_pending"
    FINALIZATION_PENDING = "finalization_pending"


@dataclass(frozen=True)
class ExecutionProgressReportV2:
    schema_version: Literal["1.0"]
    execution_id: str
    action_id: str
    transaction_id: str
    status: ExecutionProgressStatusV2
    reason_codes: tuple[str, ...]
    progress_revision: int
    progress_ref: str
    progress_digest: str


@dataclass(frozen=True)
class ExecutionProgressDraftV2:
    schema_version: Literal["1.0"]
    execution_id: str
    action_id: str
    transaction_id: str
    status: ExecutionProgressStatusV2
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class ExecutionReportOwnershipBindingV2:
    execution_id: str
    action_id: str
    mission_ref: str
    mission_revision: int
    owner_subject_id: str
    owner_principal_ref: str
    owner_principal_revision: int
    binding_digest: str


@dataclass(frozen=True)
class ExecutionReportOwnershipRefV2:
    reference: str
    revision: int
    execution_id: str
    binding_digest: str


@runtime_checkable
class ExecutionReportOwnershipStoreV2(Protocol):
    def require_by_execution_id(
        self,
        execution_id: str,
    ) -> tuple[ExecutionReportOwnershipRefV2, ExecutionReportOwnershipBindingV2]: ...


@dataclass(frozen=True)
class ActionExecutionReportEnvelopeV2:
    report: ActionExecutionReportV2
    report_revision: int
    report_ref: str
    report_digest: str


ExecutionReportViewV2: TypeAlias = ExecutionProgressReportV2 | ActionExecutionReportEnvelopeV2

InvocationExecutionOutcomeV2: TypeAlias = ExecutionProgressReportV2 | ActionExecutionReportEnvelopeV2


@dataclass(frozen=True)
class FinalizationPersistedV2:
    finalization_ref: InvocationFinalizationRefV2


@dataclass(frozen=True)
class FinalizationRetryEnqueuedV2:
    retry_ref: InvocationFinalizationRetryRefV2


FinalizationPersistenceOutcomeV2: TypeAlias = FinalizationPersistedV2 | FinalizationRetryEnqueuedV2


def canonical_finalization_persistence_outcome_digest(
    outcome: FinalizationPersistenceOutcomeV2,
) -> str:
    """RFC-8785 finalization-persistence-outcome/1.0 tagged union + exact ref."""
    ...


@dataclass(frozen=True)
class FinalizationRetryClaimV2:
    retry_ref: InvocationFinalizationRetryRefV2
    expected_revision: int
    claim_id: str
    fencing_token: int
    claim_expires_at_utc: float
    claimer_instance_id: str
    claimer_boot_id: str


class FinalizationRetryStateV2(str, Enum):
    UNBOUND = "unbound"
    PENDING = "pending"
    CLAIMED = "claimed"
    COMPLETED = "completed"


@dataclass(frozen=True)
class FinalizationRetryRecordV2:
    retry_ref: InvocationFinalizationRetryRefV2
    finalization: InvocationFinalizationRecordV2
    finalization_digest: str
    intent_ref: InvocationFinalizationIntentRefV2
    ownership_ref: ExecutionReportOwnershipRefV2
    pending_report: ActionExecutionReportEnvelopeV2 | None
    expected_previous_revision: int | None
    superseding_publication_idempotency_key: str | None
    state: FinalizationRetryStateV2
    claim_id: str | None
    fencing_token: int
    claim_expires_at_utc: float | None
    claimer_instance_id: str | None
    claimer_boot_id: str | None
    completion_receipt: FinalizationRetryCompletionReceiptV2 | None
    record_digest: str


@dataclass(frozen=True)
class FinalizationRetryCompletionReceiptV2:
    retry_ref: InvocationFinalizationRetryRefV2
    persisted_finalization_ref: InvocationFinalizationRefV2
    superseding_report_ref: str
    superseding_report_digest: str
    completion_digest: str


def canonical_finalization_retry_record_digest(
    record: FinalizationRetryRecordV2,
) -> str:
    """RFC-8785 finalization-retry/1.0; excludes record_digest itself."""
    ...


def canonical_finalization_retry_claim_digest(
    claim: FinalizationRetryClaimV2,
) -> str:
    """RFC-8785 finalization-retry-claim/1.0; covers all claim fields."""
    ...


def canonical_finalization_retry_completion_digest(
    receipt: FinalizationRetryCompletionReceiptV2,
) -> str:
    """RFC-8785 finalization-retry-completion/1.0; excludes its digest."""
    ...


@runtime_checkable
class FinalizationRetryStoreV2(Protocol):
    def bind_pending_publication(
        self,
        reference: InvocationFinalizationRetryRefV2,
        *,
        expected_retry_revision: int,
        pending_report: ActionExecutionReportEnvelopeV2,
        superseding_publication_idempotency_key: str,
    ) -> FinalizationRetryRecordV2: ...
    def list_pending(self) -> tuple[InvocationFinalizationRetryRefV2, ...]: ...
    def list_claimable(
        self,
        now_utc: float,
    ) -> tuple[InvocationFinalizationRetryRefV2, ...]: ...
    def claim(
        self,
        reference: InvocationFinalizationRetryRefV2,
        *,
        expected_revision: int,
        claim_id: str,
        claim_expires_at_utc: float,
        claimer_instance_id: str,
        claimer_boot_id: str,
    ) -> tuple[FinalizationRetryClaimV2, FinalizationRetryRecordV2]: ...
    def renew_claim(
        self,
        claim: FinalizationRetryClaimV2,
        *,
        new_expires_at_utc: float,
    ) -> tuple[FinalizationRetryClaimV2, FinalizationRetryRecordV2]: ...
    def reclaim_expired(
        self,
        reference: InvocationFinalizationRetryRefV2,
        *,
        expected_revision: int,
        expected_fencing_token: int,
        new_claim_id: str,
        new_expires_at_utc: float,
        claimer_instance_id: str,
        claimer_boot_id: str,
    ) -> tuple[FinalizationRetryClaimV2, FinalizationRetryRecordV2]: ...
    def require(
        self,
        reference: InvocationFinalizationRetryRefV2,
    ) -> FinalizationRetryRecordV2: ...
    def complete(
        self,
        claim: FinalizationRetryClaimV2,
        persisted: InvocationFinalizationRefV2,
        superseding_report: ActionExecutionReportEnvelopeV2,
    ) -> FinalizationRetryCompletionReceiptV2: ...


class FinalizationRetryReconcilerV2:
    def reconcile_once(
        self,
        reference: InvocationFinalizationRetryRefV2,
    ) -> ActionExecutionReportEnvelopeV2: ...
```

The retry record/store/reconciler are PR-5-owned finalization services (shown
here beside the public report DTOs only for final-tree readability). Enqueue
atomically mints the retry ref/record and binds the exact factory-produced
finalization digest and intent/ownership refs in state UNBOUND; at that point no
report can exist because its retry ref has only just been minted. The executor
then constructs and CAS-publishes the pending envelope carrying that ref and
calls `bind_pending_publication()` with the exact envelope, next report CAS
revision and stable idempotency key before completing the execution intent.
`expected_retry_revision` fences the retry row only; the report predecessor
revision is derived from and verified against the supplied store envelope/CAS
history, so the two revision domains cannot be confused.
`list_pending()`/`claim()` return only bound PENDING records. Startup finds an
UNBOUND record through its still-pending finalization intent, publishes the same
idempotent envelope and binds it. Claim returns a read-back
record; every persist and superseding publication revalidates those identities.
Completion accepts only the same claim/fencing token, store-read persisted
finalization and the permitted pending=True→pending=False envelope revision,
then returns a durable receipt. Crash/replay returns the same receipt; concurrent
claims, any result/transaction/status/digest mutation or a second terminal
transition fail closed.
Claim and record digests use the canonical helpers above. UNBOUND requires all
publication/claim fields null; PENDING requires the exact pending envelope and
publication key but no claim; CLAIMED additionally requires a current UTC claim
expiry, instance/boot identity and non-zero fencing token; COMPLETED requires
the durable completion receipt and no renewable claim. `renew_claim()` preserves
the token, while expiry-based reclaim increments it. Every mutation and
`complete()` verifies the current unexpired claim ID/token; a stale worker can
never publish or complete a retry.

Canonical timing:

```text
ExecutionResultV2 and ExecutionResultRefV2:
    staged and committed by the executor-owned ExecutionCommitCoordinator;
    contain no cleanup fields because outer-finally cleanup is not complete yet.

InvocationFinalizationRecordV2:
    appended after every outer-finally step has run;
    records cleanup and the effective post-cleanup status;
    never mutates the committed ExecutionResultV2.

ActionExecutionReportV2:
    assembled only after finalization;
    contains both the committed result/ref, when one exists, and finalization.
```

Before a globally committed result may become queryable or any terminal/progress
response may return, the executor durably persists
`InvocationFinalizationIntentRecordV2` and uses only its store-issued ref after
read-back. It contains only fenced recovery refs and
identity/digest evidence, never a live callback. Outer-finally cleanup and
`persist_or_enqueue()` idempotently complete the intent. Startup recovery lists
pending intent refs, reopens the typed cleanup journals, records cleanup FAILED
with `cleanup_outcome_unknown` while preserving SUCCEEDED/PARTIAL transaction
status for an already committed result (effective status becomes PARTIAL), or
uses INTERNAL_FAILURE only when no committed result exists, and
publishes a later immutable final report. Until then queries return exactly
`ExecutionProgressReportV2(FINALIZATION_PENDING)`. This progress applies only
until cleanup, a prepared finalization record and either a durable persistence
or retry-enqueue outcome exist. A durable retry enqueue permits the immutable
final envelope with `finalization_persistence_pending=True`; the execution
intent then hands ownership to `FinalizationRetryStoreV2` rather than losing the
work. The fenced retry reconciler persists the same finalization digest and
publishes exactly one later final revision with pending=False, the same
execution/action/transaction/result/committed binding, persisted ref replacing
the retry ref, and no other terminal mutation. Concurrent claim, crash between
persist/publish and replay are CAS/idempotency tested. A committed result may
exist hidden before either durable outcome, but no report falsely claims cleanup completion.
Checkout/scope/coordinator recovery refs are absent iff that owner was never
created. Once an owner exists, its durable ref is mandatory before any
return/visibility. Store canonicalization excludes no identity field and
validates the store-minted revision/digest on require; committed state is
resolved only through the coordinator recovery/marker store.
Intent completion itself is durable evidence: `complete()` validates the exact
persistence outcome and already-published envelope, persists a canonical
completion receipt and returns its readback. Same-digest replay returns the same
receipt, conflicting report/outcome fails, and `list_pending()` excludes an
intent only after that receipt exists. Recovery after publish-before-complete
loads the same envelope/idempotency key, calls `complete()` again and verifies
`require_completion()`; it never infers completion from report presence alone.

`ExecutionResultStore` and `InvocationFinalizationStore` exact APIs are created in
PR-5. Finalization exposes only
`persist_or_enqueue(record, *, intent_ref, ownership_ref) ->
FinalizationPersistenceOutcomeV2`; it atomically
persists the finalization or durably enqueues a retry. The report is constructed
only from that outcome. If neither durable operation succeeds, executor fails
closed and does not return a report that merely claims persistence is pending.
Exact invariants:

```text
finalization_persistence_pending == False
    → finalization_ref is present and durable; finalization_retry_ref is None;

finalization_persistence_pending == True
    → finalization_ref is None and finalization_retry_ref identifies the durable
      retry/outbox record.
```

The flag is exact report state, is never inferred from prose, and does not
rewrite the committed result.

Publication table is exact:

| Transaction outcome | `execution_result`/ref |
|---|---|
| globally `COMMITTED` + `SUCCEEDED` | present |
| globally `COMMITTED` + policy-accepted provider `PARTIAL` | present |
| pre-commit `FAILED`, `BLOCKED`, `UNAVAILABLE`, `TIMED_OUT`, `CANCELLED`, `INTERNAL_FAILURE` | absent |
| reconciliation pending (`ExecutionProgressStatusV2.RECONCILIATION_PENDING`) | progress report only; no execution result/finalization until a later terminal report |
| durable `FAILED_RECONCILIATION` after every participant/resource disposition is durably contained | final report with no result, `transaction_status=INTERNAL_FAILURE`, reason `execution_reconciliation_failed` and containment/audit ref |

Post-commit cleanup never mutates the committed result. It changes only the
finalization effective status. Composite routers therefore call
`require_successful_committed_result_ref()` and never infer success from the
mere presence of an arbitrary child report.
Before the exact participant/resource disposition is durable,
`FAILED_RECONCILIATION` is not published as terminal and queries remain
`RECONCILIATION_PENDING`. A terminal failed-reconciliation report never exposes
a hidden result and can never yield a child result ref.

`CommittedExecutionResultBindingV2` has an internal sentinel constructor. Only
the execution-result store participant may create it from the coordinator's
durable `COMMITTED` marker; decoders and providers cannot construct it. Its
marker/ref/digest are revalidated when the report is loaded. The helper checks
report/result/ref/finalization action, execution and transaction identity and
recomputes the canonical result digest before returning the ref.
The sole `_CommittedBindingConstructionTokenV2` instance is module-private,
never exported, pickled or decoded; an AST ratchet forbids its use outside the
execution-result store implementation. PR-5 bridges the staged literal to the
exact `ExecutionCommitStateV2.COMMITTED` record before calling the factory.
`canonical_execution_result_digest()` is PR-2-owned and uses UTF-8 RFC 8785
canonical JSON over every `ExecutionResultV2` field, tagged with
`execution-result/2.0`; Python golden vectors lock its byte/digest output.

The canonical post-decoding `ActionRequestV2` and exact `V2InputUnion` are
introduced once in PR-6 (§10.14A), after all input DTO exist. Until then no
first-party source file may annotate a field or return value with `V2InputUnion`
or `ActionRequestV2`.

Authoritative common order:

1. bounded envelope decode;
2. resolve and validate the authenticated `IngressInvocationLease`, ingress
   session, principal and mission with a non-enumerating read-only lookup; no
   catalog/provider/policy detail is exposed yet;
3. allocate execution/transaction IDs and call the single applicable
   `ExecutionCreationStoreV2.begin_root()` or `begin_child()` transaction and
   read back its receipt,
   which atomically creates the CREATED finalization intent, report-ownership
   binding and ingress recovery ref before any policy, approval, checkout or
   other recoverable owner exists;
4. resolve versioned `ActionCatalogEntry`, descriptor and mount snapshot;
5. resolve approval and `ExecutionPolicy.authorize_coarse(...)`; reserve the
   approval graph as an inert durable owner, CAS its recovery ref into the
   intent, then activate/read back it before any checkout. Leaf and router share
   this graph; a child inherits/narrows it and never opens a second graph;
6. exact typed-input decode, target extraction and trusted fact/reference snapshot resolution;
7. initial readiness and `ExecutionPolicy.authorize_deep(...)`;
8. atomic snapshot/reference checkout using that graph lease, without opening live/secret material;
9. required side-effect-free `check_bound`;
10. branch by the canonical `execution_node_kind`.

Every early terminal BLOCKED/UNAVAILABLE/CANCELLED/INTERNAL_FAILURE branch uses
that same intent: checkpoint the primary outcome, perform applicable cleanup,
persist/enqueue finalization, CAS-publish the final envelope and complete the
intent. No denial path returns an untracked raw report.

`LEAF` branch:

11. through `IntentBoundAttemptLeaseFactoryV2`, reserve an inert concrete
    attempt, CAS its recovery ref into the intent, then activate/read back the
    `PENDING` lease; the executor never calls graph `reserve_attempt()` directly;
12. reserve inert invocation-scope and commit-coordinator records, CAS both refs
    into the current intent, issue/read back the participant authority binding
    from creation+intent+checkout+coordinator evidence, then activate both owners
    and construct their restricted staging/participant/scope facades. Any crash
    or failure from the first reservation onward is discoverable by outer-finally
    or startup recovery;
13. final readiness recheck;
14. create the PENDING phase-lease controller/view, open fenced material, bind
    provider views, assert checkout current, call
    `readiness_registry.assert_current(fresh_readiness)` immediately before the
    attempt transition, then atomically `start()` the attempt;
15. `ProviderCallBoundary` activates that same lease view and calls
    `execute_bound` with restricted provider facades;
16. `ProviderCallBoundary` revokes that phase lease in its own `finally`, before
    result normalization; every cached facade/material capability is now inert;
17. executor consumes/stages core-owned sensitive handles, constructs a
    read-only result view, and calls required `verify_bound`;
18. after successful verification no provider code runs again: the coordinator
    prepares all reversible participants, then the executor obtains and
    store-read-validates one `ExecutionNoReturnAdmissionReceiptV2` against the
    current graph cancellation revision and the exact decision/effect identity.
    With a terminal effect it attaches/read-backs
    `EffectDispatchAuthorizationV2` containing that admission ref/digest before
    `dispatch_terminal_effect(operation, admission)`; with no terminal effect it
    calls `decide_commit(admission)` directly and rolls forward. A cancelled
    admission aborts without dispatch. The terminal-effect outcome is matched
    exhaustively: `EFFECT_CONFIRMED` persists `decide_commit(admission)` and
    rolls forward; `FAILED_NO_EFFECT` persists `decide_abort()` and rolls back;
    `IN_DOUBT` publishes progress and transfers probe/containment custody. Only
    the committed branch hidden-commits, finalizes visibility and completes the
    committed result binding (it does not publish a report);
19. the `IN_DOUBT` branch durably hands off coordinator, checkout, scope, graph
    and cancellation custody, performs only ingress and current-process
    controller-binding bookkeeping, publishes
    `ExecutionProgressReportV2(RECONCILIATION_PENDING)`, and returns progress;
    it does not close fenced owners, persist finalization or publish a final
    envelope. Terminal outer-finally cleanup proceeds only after `COMMITTED`,
    `ROLLED_BACK`, or durably contained `FAILED_RECONCILIATION`;
20. for that terminal branch, persist/enqueue finalization, construct the final report, CAS
    `ExecutionReportStoreV2.publish_final(...)` to a store-issued envelope,
    complete the durable finalization intent with that same envelope, and return
    the envelope.

The executor creates the finalization intent atomically with the ingress
recovery/ownership record immediately after allocating the execution/transaction
identity and before constructing the first recoverable owner. Each checkout,
scope, coordinator, approval graph and attempt reservation is first inertly
reserved, attached by store CAS, and only then activated before it can escape,
dispatch an effect or contribute a visible result. Thus startup can
discover every live execution even if the process dies between owner creation
and the final report. The authoritative intent/checkpoint API is in §8.6.

`InvocationFinalizationFactoryV2` is the sole record constructor and applies
the §8.8 precedence table exactly: primary FAILED/UNAVAILABLE/TIMED_OUT/
CANCELLED/INTERNAL_FAILURE remains primary; SUCCEEDED plus cleanup FAILED becomes
PARTIAL with `invocation_cleanup_failed`; PARTIAL plus cleanup FAILED remains
PARTIAL and adds that reason once; successful/not-required cleanup preserves the
transaction status. `ActionExecutionReportV2.__post_init__` recomputes this
expected status and rejects a record not created by the factory/token path.

`COMPOSITE_ROUTER` branch:

11. obtain a fresh readiness snapshot, compare action/mount/dependency/daemon
    identity and generation with the checked snapshot, re-run
    `checkout_bundle.assert_current()` for facts/references/approval, then
    `authorize_router_step(...)`; unavailable returns without selecting a child;
    the parent reserves/starts no approval attempt and opens no material;
12. reserve inert parent scope and commit coordinator records, CAS both refs
    into the parent intent, then activate
    them; these owners remain executor-private and are required for a durable
    asynchronous continuation even though the router receives no scope or
    coordinator capability;
13. create the PENDING router phase-lease controller/view and call
    `ProviderCallBoundary.invoke_route(...)` with
    `BoundCompositeRouterContextV2`, which contains only
    immutable snapshots, readiness, targets, budget/lineage and a narrowed child
    execution facade—no staging, participant, secret/live material or scope
    ownership capability;
14. boundary revokes the router phase lease on return/exception; selected child
    re-enters the entire executor at step 1 and is the only node
    that reserves/starts a concrete approval use;
15. for a terminal successful child, validate the private completion receipt;
    executor (not router code) normalizes/verifies the parent composite result,
    stages parent audit/trace/result and completes the parent's committed result
    binding. Then run outer-finally cleanup, persist/enqueue finalization, CAS
    publish the parent report envelope, complete the parent intent and return
    that envelope;
16. for `CompositeRouteProgressV2`: begin/read back the pending-child record;
    reserve the continuation; CAS its RESERVED ref into the intent; CAS/read back
    custody of checkout, scope, coordinator and approval graph; checkpoint the
    CUSTODY_TRANSFERRED continuation ref; consume the original ingress lease
    exactly once; then return progress. Outer-finally skips the transferred
    owners. This is custody transfer, not a second intent owner; the intent stays
    store-owned and the graph is closed later only when its recovery ref says
    `owner=True`. Do not verify, stage a parent result or finalize until the
    child has a terminal or durably contained disposition.

Any implementation that sends a router through the leaf material/attempt path,
or gives a router an “empty” provider context containing write capabilities, is
non-conforming.

### 4.0A. Exact foundation supporting types and ownership

The following supporting types are created before any consumer and have one
canonical owner.

#### Authentication types — `core/auth/types.py` (PR-2)

```python
class IngressKind(str, Enum):
    INTERACTIVE_CLI = "interactive_cli"
    HTTP_API = "http_api"
    C2_CONTROL = "c2_control"
    INTERNAL_SERVICE = "internal_service"


class SubjectType(str, Enum):
    OPERATOR = "operator"
    SERVICE = "service"


class AuthenticationMethod(str, Enum):
    PASSWORD = "password"
    API_KEY = "api_key"
    MTLS = "mtls"
    OS_PEER_API_KEY = "os_peer_api_key"
    INTERNAL_ATTESTATION = "internal_attestation"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"
    EXPIRED = "expired"
    EXHAUSTED = "exhausted"
```

#### Cancellation — `core/actions/cancellation.py` (PR-2)

```python
@runtime_checkable
class CancellationToken(Protocol):
    @property
    def token_id(self) -> str: ...
    @property
    def cancelled_at(self) -> float | None: ...
    @property
    def reason_code(self) -> str | None: ...
    def is_cancelled(self) -> bool: ...
    def raise_if_cancelled(self) -> None: ...
    def wait(self, timeout_seconds: float | None) -> bool: ...


class _CancellationStateV2:
    token_id: str
    condition: threading.Condition
    cancelled_at: float | None
    reason_code: str | None


class ExecutorCancellationController:
    """The only production cancellation source/controller."""

    _state: _CancellationStateV2
    _token: _ExecutorCancellationToken

    def __init__(self, token_id: str) -> None: ...
    @property
    def token(self) -> CancellationToken: ...
    def cancel(self, *, reason_code: str, cancelled_at: float | None = None) -> bool: ...


class _ExecutorCancellationToken:
    """Private concrete read-only token backed by one controller-owned condition."""

    _state: _CancellationStateV2

    def __init__(self, state: _CancellationStateV2, *, _factory_key: object) -> None: ...
    @property
    def token_id(self) -> str: ...
    @property
    def cancelled_at(self) -> float | None: ...
    @property
    def reason_code(self) -> str | None: ...
    def is_cancelled(self) -> bool: ...
    def raise_if_cancelled(self) -> None: ...
    def wait(self, timeout_seconds: float | None) -> bool: ...
```

`ExecutorCancellationController` owns the mutable cancellation state and creates
exactly one private `_ExecutorCancellationToken`. Root executor creates the
controller; child budgets share only the same read-only token. Tokens are
non-serializable, cannot be caller-implemented/injected, and cancellation is
monotonic/idempotent. Provider boundaries receive only `CancellationToken`,
never the controller.

#### Opaque secret capability — `core/secrets.py` (PR-5)

PR-5 creates the sole `SecretValue` owner before PR-6 agent/build DTO import it:
PR-4 `core/actions/sensitive_integrity.py` is the earlier, dependency-free sole
owner of `SensitiveIntegrityTagV2`. PR-5 imports that DTO and
`core/actions/zeroizable_buffers.py` owns `ZeroizableSensitiveBufferV2`/lease,
`OwnedZeroizableSensitiveBufferV2`/lease and
`ZeroizableDestinationBufferV2`; the later provider-result section imports and
shows those contracts for reference but PR-7 does not create/redeclare them.

```python
class SecretValueState(str, Enum):
    AVAILABLE = "available"
    LEASED = "leased"
    CONSUMED = "consumed"
    CLEARED = "cleared"


@runtime_checkable
class SecretValue(Protocol):
    @property
    def value_id(self) -> str: ...
    @property
    def byte_length(self) -> int: ...
    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...
    @property
    def state(self) -> SecretValueState: ...

    def acquire_single_use(
        self,
        *,
        consumer_id: str,
    ) -> OwnedSecretValueLeaseV2: ...

    def clear(self) -> None: ...


class _SecretValueConstructionTokenV2:
    pass


class OpaqueSecretValueV2:
    """Sole production SecretValue implementation backed by owned zeroizable storage."""

    _value_id: str
    _buffer: OwnedZeroizableSensitiveBufferV2
    _state: SecretValueState
    _clear_requested: bool
    _lock: threading.RLock

    @classmethod
    def _from_owned_buffer(
        cls,
        *,
        value_id: str,
        buffer: OwnedZeroizableSensitiveBufferV2,
        _token: _SecretValueConstructionTokenV2,
    ) -> OpaqueSecretValueV2: ...
    @property
    def value_id(self) -> str: ...
    @property
    def byte_length(self) -> int: ...
    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...
    @property
    def state(self) -> SecretValueState: ...
    def acquire_single_use(self, *, consumer_id: str) -> OwnedSecretValueLeaseV2: ...
    def clear(self) -> None: ...


class OwnedSecretValueLeaseV2:
    """Parent-aware lease; close updates the SecretValue state under one lock."""

    _parent: OpaqueSecretValueV2
    _buffer_lease: OwnedZeroizableSensitiveBufferLeaseV2
    _closed: bool

    @property
    def buffer_id(self) -> str: ...
    @property
    def lease_id(self) -> str: ...
    @property
    def byte_length(self) -> int: ...
    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...
    def read_into(self, destination: ZeroizableDestinationBufferV2) -> int: ...
    def close_and_zeroize(self) -> None: ...


class OpaqueSecretValueFactoryV2:
    """Sole concrete construction owner used by SecretStore and legacy adapter."""

    _construction_token: _SecretValueConstructionTokenV2

    def from_owned_buffer(
        self,
        *,
        value_id: str,
        buffer: OwnedZeroizableSensitiveBufferV2,
    ) -> OpaqueSecretValueV2: ...


class LegacySecretValueAdapterV2:
    """Reviewed adapter from an existing secret:// record to OpaqueSecretValueV2."""

    _secret_store: SecretStore
    _factory: OpaqueSecretValueFactoryV2

    def checkout(self, secret_ref: str, *, consumer_id: str) -> OpaqueSecretValueV2: ...


class SecretStore:
    # Existing V1 reveal() remains compatibility-only. V2 may call only this API.
    def checkout_zeroizable(
        self,
        secret_ref: str,
        *,
        consumer_id: str,
    ) -> OpaqueSecretValueV2: ...
```

The protocol has no `str`, `bytes`, reveal, serialization or repr surface.
`OpaqueSecretValueV2` is the concrete implementation; existing `secret://`
records cross the V2 boundary only through `LegacySecretValueAdapterV2`, whose
implementation delegates exclusively to `SecretStore.checkout_zeroizable()`.
That store API decrypts directly into core-owned mutable storage and never calls
`reveal()`, decodes to `str` or constructs an immutable plaintext `bytes` DTO.
All exported mutable views are context-managed and released before zeroization;
copy/transfer factories wipe the caller-owned mutable source in `finally`.
The contract does not claim it can wipe unavoidable native-library temporaries.
PR-6 imports `SecretValue` from `core.secrets`. PR-14 encoders acquire a
single-use lease, copy only into a `ZeroizableDestinationBufferV2`, and in one
mandatory `finally` destroy both destination and source lease. No later PR
redeclares the protocol or implementation.

`acquire_single_use()` holds the parent lock, permits only AVAILABLE→LEASED and
returns the parent-aware lease. Lease close is idempotent and, under the same
lock, zeroizes storage before LEASED→CONSUMED (or →CLEARED when a concurrent
`clear()` set `_clear_requested`). `clear()` during LEASED never exposes or
reuses storage: it atomically sets that flag, denies further acquisition, and
the live lease performs final zeroization/state transition; cleanup may wait for
or fence that lease but cannot restore AVAILABLE. Success, exception and
concurrent-clear tests lock this state machine.

Sensitive plaintext never uses a public unkeyed content digest. PR-4 owns the
dependency-free `SensitiveIntegrityTagV2(key_id, algorithm, domain, tag)` DTO;
PR-5 owns the concrete store/executor-only domain-separated authenticator
(versioned HMAC-SHA-256 in v2) and zeroizable buffers. Secret
values, zeroizable sensitive buffers, sensitive handles/stage requests and
sensitive draft refs may carry the opaque tag as closed transaction integrity
metadata; key material and plaintext never cross, providers cannot mint/verify
tags, and tags never enter report/audit payloads. The factory computes the tag
while ingesting mutable source. Ordinary SHA-256 remains only for non-sensitive
artifact content, ciphertext/envelopes and canonical public DTOs. Legacy
`content_digest` property names for sensitive plaintext are forbidden.

#### Policy request snapshot — `core/actions/policy_snapshots.py` (PR-2 then PR-4)

PR-2 creates only the dependency-free header:

```python
@dataclass(frozen=True)
class ActionPolicyRequestHeaderV2:
    schema_version: Literal["2.0"]
    request_id: str
    action_id: str
    root_action_id: str
    parent_action_id: str | None
    execution_graph_id: str
    capability_class: str
    killchain_stage: str | None
    operation_id: str | None
```

PR-4 **MODIFIES the same file** after target/fact/reference DTO exist and adds the
only final request snapshot:

```python
@dataclass(frozen=True)
class ActionPolicyRequestSnapshot:
    header: ActionPolicyRequestHeaderV2
    targets: tuple[ExtractedActionTarget, ...]
    principal: PrincipalAuthorizationSnapshot
    mission: MissionAuthorizationSnapshot
    approval: ApprovalAuthorizationSnapshot | None
    facts: tuple[TrustedFactSnapshot, ...]
    references: tuple[ReferenceMetadataSnapshot, ...]


@runtime_checkable
class ActionPolicyRequestSnapshotFactoryV2(Protocol):
    def build(
        self,
        *,
        static_state: CanonicalActionStaticState,
        bridge: RootExecutionBridge | ChildExecutionBridge,
        operation_id: str | None,
        targets: tuple[ExtractedActionTarget, ...],
        principal: PrincipalAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
        approval: ApprovalAuthorizationSnapshot | None,
        facts: tuple[TrustedFactSnapshot, ...],
        references: tuple[ReferenceMetadataSnapshot, ...],
    ) -> ActionPolicyRequestSnapshot: ...
```

PR-2 never imports PR-4 types. The final snapshot contains request-scoped
canonical snapshots only; provider mount/readiness state is supplied separately
through `CanonicalActionState` and never decoded from caller input.
The executor-only factory is the only constructor path. It requires
`descriptor.action_id == mount.spec.action_id == header.action_id`, and copies
capability/stage only from the descriptor projection. It binds request/root/
parent/graph IDs to the validated bridge and lineage and rejects an operation
not admitted by the action operation catalog. `authorize_coarse()` and
`authorize_deep()` both recheck header/static-state identity before evaluating
policy; mismatches fail closed and never create another semantics owner.
PR-4 imports the two PR-2 bridge classes directly; the later PR-6 convenience
alias `ExecutionBridge` is not a PR-4 dependency.

#### Trusted fact storage types — `core/actions/trusted_facts.py` (PR-4)

`AssessmentStatus` is not redefined. V2 imports the existing canonical enum from
`core.ai.fact_assessment`, together with the existing freshness/coverage enums:

```python
from core.ai.fact_assessment import (
    AssessmentStatus,
    EvidenceCoverageStatus,
    FactFreshnessStatus,
)
```

The existing `AssessmentStatus` values remain authoritative:

```text
OBSERVED
INFERRED
VERIFIED
CONTRADICTED
```

V2 adds only action-specific fact type and trust-level types:

```python
class TrustedFactType(str, Enum):
    CONFIRMED_WINDOWS_ACCESS = "confirmed_windows_access"
    AD_ENVIRONMENT_DETECTED = "ad_environment_detected"
    CONFIRMED_AD_ACCESS = "confirmed_ad_access"
    SMB_SERVICE_AVAILABLE = "smb_service_available"
    WINRM_SERVICE_AVAILABLE = "winrm_service_available"
    DCOM_SERVICE_AVAILABLE = "dcom_service_available"
    CONFIRMED_SSH_ACCESS = "confirmed_ssh_access"
    CONFIRMED_PIVOT = "confirmed_pivot"
    APPROVED_C2_SCOPE = "approved_c2_scope"
    CONFIRMED_TARGET_ACCESS = "confirmed_target_access"
    C2_CHANNEL_AUTHORIZED = "c2_channel_authorized"
    C2_AGENT_ENROLLED = "c2_agent_enrolled"


class TrustedFactTrustLevelV2(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class StoredFactRecord:
    schema_version: str
    fact_ref: str
    revision: int
    mission_id: str
    target: str
    fact_type: str
    assessment_status: str
    trust_level: str
    freshness_status: str
    coverage_status: str
    source_execution_ids: tuple[str, ...]
    payload_digest: str
    expires_at: float | None
```

`TrustedFactDecoder` is the only component that converts stored strings to:

```text
AssessmentStatus
TrustedFactTrustLevelV2
FactFreshnessStatus
EvidenceCoverageStatus
```

A trusted precondition requires every positive condition exactly:

```text
assessment_status == AssessmentStatus.VERIFIED
trust_level == TrustedFactTrustLevelV2.TRUSTED
freshness_status == FactFreshnessStatus.FRESH
coverage_status == EvidenceCoverageStatus.COMPLETE
```

`TrustedFactTrustLevelV2.UNKNOWN`, `FactFreshnessStatus.UNKNOWN`, and
`EvidenceCoverageStatus.UNKNOWN` are explicit fail-closed denials. Any unknown,
stale, degraded, untrusted, contradicted or non-verified value blocks the
precondition; absence of a value never defaults to trusted/fresh/complete.

No second `AssessmentStatus`, freshness enum or evidence-coverage enum is
allowed in V2 modules.

#### C2 page/result DTO — `core/c2/result_models.py` (PR-14)

PR-14 does not import `AgentTaskStatus` or any PR-15 agent-wire DTO. It owns a
separate control/read status enum and exact page DTO:

```python
class ResultRecordStatusV1(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    INVALID_PAYLOAD = "invalid_payload"
    LEGACY_UNASSIGNED = "legacy_unassigned"


@dataclass(frozen=True)
class AgentSummaryV1:
    agent_ref: str
    mission_id: str
    revision: int
    state: str
    hostname: str
    os: C2TargetOS | None
    arch: C2TargetArch | None
    last_seen: float | None


@dataclass(frozen=True)
class AgentPageV1:
    items: tuple[AgentSummaryV1, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class ResultSummaryV1:
    result_ref: str
    task_ref: str
    agent_ref: str
    mission_id: str
    revision: int
    status: ResultRecordStatusV1
    result_schema_id: str
    completed_at: float
    acknowledged: bool


@dataclass(frozen=True)
class ResultPageV1:
    items: tuple[ResultSummaryV1, ...]
    next_cursor: str | None


@dataclass(frozen=True)
class ResultAckBatchV1:
    acknowledgements: tuple[ResultAcknowledgementRecordV1, ...]
    rejected_refs: tuple[str, ...]


@dataclass(frozen=True)
class PurgeResultV1:
    purged_count: int
    next_cursor: str | None
```

PR-15 maps a decoded `AgentTaskStatus` to `ResultRecordStatusV1` when it writes a
result row. PR-14 has no dependency on `AgentTaskEnvelopeV12`,
`AgentTaskResultV12` or `AgentTaskDeliveryAckV12`.

All control-service signatures use the exact `*V1` names. Bare `AgentPage`,
`ResultPage` and `PurgeResult` aliases are forbidden.

### 4.1. Action request не содержит ingress authority

Для V2 user-decoded `ActionRequest` не содержит и не принимает:

```text
ingress_session_ref
principal_ref
subject_id
subject_type
role
authentication_method
peer UID/GID/PID
transport/channel binding
```

Caller может передать только business references, которые сами не являются authentication authority:

```python
mission_ref: str
approval_ref: str | None
```

Даже валидный `ingress_session_ref`, скопированный из другого запроса, не даёт права запустить action.

Authoritative ingress identity поступает в executor только через текущую, уже аутентифицированную ingress invocation.

### 4.2. `IngressInvocationLease` привязан к реальному ingress-сеансу

Создать non-serializable, single-invocation объект:

```python
@dataclass(frozen=True, repr=False)
class IngressInvocationLease:
    lease_id: str
    ingress_session_ref: str
    ingress_session_revision: int
    principal_ref: str
    principal_revision: int

    ingress_kind: IngressKind
    authenticated_peer_id: str
    authenticated_peer_uid: int | None
    authenticated_peer_gid: int | None
    authenticated_peer_pid: int | None

    transport_instance_id: str
    transport_binding_digest: str
    invocation_nonce_digest: str
    bound_request_id: str
    issued_at: float
    expires_at: float
```

Lease создаёт только reviewed ingress adapter после реальной authentication:

```text
interactive CLI authentication/session manager
HTTP/API authentication middleware
C2 control peer + operator authentication
reviewed internal service ingress
```

Lease передаётся только в root V2 entrypoint и не входит в decoded payload:

```python
executor.run_v2(
    action_id,
    serialized_envelope,
    ingress_lease=lease,
)
```

The public root wrapper derives its unforgeable `ExecutionBudgetLeaseV2`
internally; no ingress caller supplies `ExecutionBudget` or cancellation token.

`ActionExecutor.run()` остаётся V1 entrypoint. Для V2 существует ровно один
public root wrapper `run_v2(...)` и ровно один internal method
`_run_v2_internal(...)`. Других V2 execution entrypoints нет.

`IngressSessionStore.resolve_invocation_lease()` атомарно проверяет:

```text
lease существует и не использована
lease bound_request_id совпадает с текущим request_id
session active, not expired, not revoked
session revision совпадает
principal revision совпадает
peer UID/GID/PID или authenticated peer ID совпадает
transport instance ID совпадает
transport/channel binding digest совпадает
invocation nonce не переиспользован
```

После завершения action invocation lease помечается `CONSUMED` в outer `finally`. Она не может использоваться повторно.

Запрещено:

```text
создавать lease из ActionRequest
декодировать lease из JSON/CLI args
принимать principal_ref отдельно от lease
переиспользовать lease на другой connection/TTY/HTTP request/socket peer
использовать expired/revoked/copied lease
```

### 4.3. Principal выводится только из validated ingress lease

Executor получает principal следующим образом:

```text
current IngressInvocationLease
→ IngressSessionStore.resolve_invocation_lease(...)
→ canonical ingress session
→ canonical PrincipalAuthorizationSnapshot
```

```python
@dataclass(frozen=True)
class IngressSessionAuthorizationSnapshot:
    schema_version: str
    ingress_session_ref: str
    revision: int
    principal_ref: str
    subject_id: str
    subject_type: SubjectType
    authentication_method: AuthenticationMethod
    ingress_kind: IngressKind
    authenticated_peer_id: str
    transport_binding_digest: str
    issued_at: float
    expires_at: float
    revoked_at: float | None
```

```python
@dataclass(frozen=True)
class PrincipalAuthorizationSnapshot:
    schema_version: str
    principal_ref: str
    revision: int
    subject_id: str
    subject_type: SubjectType
    active: bool
    roles: tuple[str, ...]
    capabilities: tuple[str, ...]
    authenticated_at: float
    expires_at: float | None
```

Mandatory invariants:

```text
lease.ingress_session_ref == ingress_session.ingress_session_ref
lease.ingress_session_revision == ingress_session.revision
lease.principal_ref == ingress_session.principal_ref
lease.principal_ref == principal.principal_ref
lease.principal_revision == principal.revision
ingress_session.subject_id == principal.subject_id
current peer/channel binding == lease peer/channel binding
```

Router child не создаёт новый ingress-сеанс. Parent executor выдаёт internal `ChildIngressLease`, производный от той же validated parent lease:

```text
same ingress session
same principal
same authenticated peer/channel
new child request ID
same execution graph
bounded child depth
```

Caller не может создать `ChildIngressLease`.

### 4.4. Trusted mission snapshot

```python
@dataclass(frozen=True)
class MissionAuthorizationSnapshot:
    schema_version: str
    mission_ref: str
    revision: int
    mission_id: str
    active: bool
    permitted_subject_ids: tuple[str, ...]
    target_scope: TargetScopeSnapshot
    permitted_capabilities: tuple[str, ...]
    permitted_stages: tuple[str, ...]
    expires_at: float | None
```

### 4.5. `ApprovalAuthorizationSnapshot`

```python
@dataclass(frozen=True)
class ApprovalAuthorizationSnapshot:
    schema_version: str
    approval_ref: str
    revision: int
    approval_id: str

    mission_id: str
    subject_id: str
    approver_subject_id: str

    permitted_root_action_ids: tuple[str, ...]
    permitted_concrete_action_ids: tuple[str, ...]
    permitted_capabilities: tuple[str, ...]
    permitted_killchain_stages: tuple[str, ...]
    target_scope: TargetScopeSnapshot
    permitted_operation_ids: tuple[str, ...]

    status: ApprovalStatus
    issued_at: float
    expires_at: float
    max_uses: int
    remaining_uses: int
```

Caller передаёт только `approval_ref`. Все поля разрешает executor.

### 4.6. Manual gate

Для `ActionDescriptorV2.manual_gate=true` обязательны:

```text
ingress session active, unexpired and peer-bound
principal active
principal subject_type == OPERATOR
mission active
principal является участником mission
approval_ref присутствует
approval ACTIVE и не истёк
approval mission_id == mission mission_id
approval subject_id == ingress/principal subject_id
root action разрешён approval
concrete action разрешён approval
capability разрешена approval
kill-chain stage разрешена approval
operation разрешена approval, если применимо
все extracted targets входят в approval target_scope
remaining_uses > 0
```

### 4.7. Kill-chain stage gate

Для V2 stage берётся только из canonical `ActionDescriptorV2`:

```text
unknown stage → deny
stage disabled in config → deny
stage отсутствует в mission → deny
stage отсутствует в approval → deny
approval не обходит disabled stage
```

### 4.8. Единая approval state machine

Использовать только следующий API:

class ApprovalExecutionLease:
    def open_graph(...): ...
    def authorize_router_step(...): ...
    def reserve_attempt(...) -> ApprovalAttemptLease: ...
    def close_graph(...): ...

class ApprovalAttemptLease:
    def start(...) -> None: ...
    def release_before_start(...) -> None: ...
    def state(...) -> AttemptLeaseState: ...

```python
class AttemptLeaseState(str, Enum):
    PENDING = "pending"
    STARTED = "started"
    RELEASED = "released"
```

`AttemptLeaseState` принадлежит только `core/auth/approval_leases.py` (PR-2).
Duplicate/stringly-typed state definitions запрещены.

Rules:

- open_graph и router authorization расходуют zero uses;
- checkout coordinator валидирует graph lease/revision, но не резервирует attempt;
- reserve_attempt вызывается executor ровно один раз для выбранного concrete leaf;
- start атомарно выполняет PENDING → STARTED и уменьшает remaining_uses;
- release_before_start выполняет PENDING → RELEASED;
- после STARTED use никогда не возвращается;
- legacy approval attempt/commit aliases удалить;
- automatic fallback после STARTED запрещён;
- root executor закрывает graph в outer finally;
- child executor не закрывает shared graph.

## Child ingress

Root IngressInvocationLease привязан к root request и остаётся действительным
до завершения execution graph.

Каждый child получает новый internal ChildIngressLease:

- derived only by IngressSessionStore;
- bound to child request_id;
- bound to parent execution ID и execution graph;
- inherits session/principal/peer/channel revisions;
- single-use;
- separately consumed after child invocation.

Child не переиспользует root lease напрямую и не может создать новый ingress
session или approval budget.

### 4.8A. Exact V2 executor API, staged typing и child bridge

```python
@dataclass(frozen=True, repr=False)
class ChildIngressLease:
    lease_id: str
    lease_revision: int
    parent_ingress_lease_id: str
    root_execution_id: str
    ingress_session_ref: str
    ingress_session_revision: int
    principal_ref: str
    principal_revision: int
    authenticated_peer_id: str
    authenticated_peer_uid: int | None
    authenticated_peer_gid: int | None
    authenticated_peer_pid: int | None
    transport_instance_id: str
    transport_binding_digest: str
    bound_child_request_id: str
    parent_execution_id: str
    execution_graph_id: str
    child_depth: int
    issued_at: float
    expires_at: float


@dataclass(frozen=True, repr=False)
class RootExecutionBridge:
    ingress_lease: IngressInvocationLease
    authority: RootExecutionAuthorityBundleV2
    lineage: ExecutionLineage


@dataclass(frozen=True, repr=False)
class ChildExecutionBridge:
    ingress_lease: ChildIngressLease
    budget_lease: ExecutionBudgetLeaseV2
    lineage: ExecutionLineage
    approval_graph_lease: ApprovalExecutionLease
    selected_child_action_id: str
    parent_decision_trace_ref: str


@dataclass(frozen=True, repr=False)
class RootExecutionAuthorityBundleV2:
    """Private root-authority output; never accepted from ingress input."""

    budget_lease: ExecutionBudgetLeaseV2
    cancellation_controller: ExecutorCancellationController = field(
        repr=False,
        compare=False,
    )


class _ExecutionBudgetConstructionTokenV2:
    pass


@runtime_checkable
class ExecutionBudgetLeaseRegistryV2(Protocol):
    def register(self, lease: ExecutionBudgetLeaseV2) -> None: ...
    def require_current(self, lease_id: str) -> ExecutionBudgetLeaseV2: ...


@dataclass(frozen=True, init=False, repr=False)
class ExecutionBudgetLeaseV2:
    lease_id: str
    ingress_lease_id: str
    request_id: str
    budget: ExecutionBudget
    parent_budget_lease_id: str | None
    policy_revision: int
    lease_digest: str

    @classmethod
    def _from_authority(
        cls,
        *,
        _token: _ExecutionBudgetConstructionTokenV2,
        lease_id: str,
        ingress_lease_id: str,
        request_id: str,
        budget: ExecutionBudget,
        parent_budget_lease_id: str | None,
        policy_revision: int,
        lease_digest: str,
    ) -> ExecutionBudgetLeaseV2: ...


@runtime_checkable
class ExecutionBudgetAuthorityV2(Protocol):
    def issue_root(
        self,
        *,
        ingress_lease: IngressInvocationLease,
        bounded_envelope: BoundedActionRequestV2Envelope,
    ) -> RootExecutionAuthorityBundleV2: ...

    def narrow_child(
        self,
        *,
        parent: ExecutionBudgetLeaseV2,
        child_request_id: str,
        child_action_id: str,
    ) -> ExecutionBudgetLeaseV2: ...

    def validate_root(
        self,
        lease: ExecutionBudgetLeaseV2,
        *,
        ingress_lease: IngressInvocationLease,
        request_id: str,
    ) -> ExecutionBudget: ...

    def validate_child(
        self,
        lease: ExecutionBudgetLeaseV2,
        *,
        parent: ExecutionBudgetLeaseV2,
        child_lease: ChildIngressLease,
        child_action_id: str,
    ) -> ExecutionBudget: ...


class OwnedExecutionBudgetAuthorityV2:
    """Sole production authority and issuer-registry owner."""

    _construction_token: _ExecutionBudgetConstructionTokenV2
    _lease_registry: ExecutionBudgetLeaseRegistryV2

    def issue_root(
        self,
        *,
        ingress_lease: IngressInvocationLease,
        bounded_envelope: BoundedActionRequestV2Envelope,
    ) -> RootExecutionAuthorityBundleV2: ...
    def narrow_child(
        self,
        *,
        parent: ExecutionBudgetLeaseV2,
        child_request_id: str,
        child_action_id: str,
    ) -> ExecutionBudgetLeaseV2: ...
    def validate_root(
        self,
        lease: ExecutionBudgetLeaseV2,
        *,
        ingress_lease: IngressInvocationLease,
        request_id: str,
    ) -> ExecutionBudget: ...
    def validate_child(
        self,
        lease: ExecutionBudgetLeaseV2,
        *,
        parent: ExecutionBudgetLeaseV2,
        child_lease: ChildIngressLease,
        child_action_id: str,
    ) -> ExecutionBudget: ...
```

`ExecutionBudgetLeaseV2` has a module-private construction token and is minted
only by exact concrete `OwnedExecutionBudgetAuthorityV2` from authenticated ingress class,
mission policy, server maxima and `time.monotonic()`. User payload, plugin,
router and public API cannot choose a budget/deadline or construct a lease.
For a root only, that authority atomically creates the sole
`ExecutorCancellationController`, embeds its private token in the budget and
returns `RootExecutionAuthorityBundleV2`; no later service creates a duplicate
controller. The root bridge carries that private bundle. Child bridges inherit
only a narrowed budget/token plus lineage; PR-5 resolves the durable current
cancellation row by the stable root/graph/token identity rather than importing a
future PR-5 ref into the independently type-checked PR-2 bridge.
Child leases can only reduce deadline/output/depth/count limits and bind the
child request/action. Every executor boundary validates concrete type, private
token provenance through the authority-side issuer registry, ingress/request
identity, parent relation, policy revision, digest and exact executor-created
cancellation-token concrete type. `_run_v2_internal` calls `validate_root()` or
`validate_child()` before reading any budget field; structural/forged leases or
cancellation tokens fail closed.

PR-2 создаёт только concrete `ChildIngressLease`, `RootExecutionBridge`,
`ChildExecutionBridge` и private `RootExecutionAuthorityBundleV2`. Имена
`ExecutionBridge` и `V2ExecutionSource` в PR-2
не существуют: оба alias зависят от `ActionRequestV2` и создаются только в PR-6.

PR-2 must remain independently type-checkable. It therefore implements only the
root/envelope pair:

```python
class ActionExecutor:
    def run_v2(
        self,
        action_id: str,
        serialized_envelope: bytes,
        *,
        ingress_lease: IngressInvocationLease,
    ) -> InvocationExecutionOutcomeV2:
        bounded = self.request_v2_decoder.decode(serialized_envelope)
        authority = self.budget_authority.issue_root(
            ingress_lease=ingress_lease,
            bounded_envelope=bounded,
        )
        bridge = self._new_root_bridge(bounded, ingress_lease, authority)
        return self._run_v2_internal(action_id, bounded, bridge=bridge)

    def _run_v2_internal(
        self,
        action_id: str,
        source: BoundedActionRequestV2Envelope,
        *,
        bridge: RootExecutionBridge,
    ) -> InvocationExecutionOutcomeV2: ...  # fail closed at the unregistered exact-decoder boundary
```

PR-6 creates `ActionRequestV2` and `V2InputUnion`, then modifies the same single
internal method with overloads; it does not create a second internal API:

```python
V2ExecutionSource: TypeAlias = BoundedActionRequestV2Envelope | ActionRequestV2
ExecutionBridge: TypeAlias = RootExecutionBridge | ChildExecutionBridge


@overload
def _run_v2_internal(
    self,
    action_id: str,
    source: BoundedActionRequestV2Envelope,
    *,
    bridge: RootExecutionBridge,
) -> InvocationExecutionOutcomeV2: ...


@overload
def _run_v2_internal(
    self,
    action_id: str,
    source: ActionRequestV2,
    *,
    bridge: ChildExecutionBridge,
) -> InvocationExecutionOutcomeV2: ...


def _run_v2_internal(
    self,
    action_id: str,
    source: V2ExecutionSource,
    *,
    bridge: ExecutionBridge,
) -> InvocationExecutionOutcomeV2: ...
```

Допустимы только пары:

```text
RootExecutionBridge  + BoundedActionRequestV2Envelope
ChildExecutionBridge + ActionRequestV2
```

До любого catalog lookup, ingress checkout, readiness, policy или approval
reservation child path обязан fail closed проверить:

```text
action_id argument == request.action_id == bridge.selected_child_action_id
request.request_id == bridge.ingress_lease.bound_child_request_id
bridge.lineage.root_execution_id == bridge.ingress_lease.root_execution_id
bridge.lineage.parent_execution_id == bridge.ingress_lease.parent_execution_id
bridge.lineage.execution_graph_id == bridge.ingress_lease.execution_graph_id
bridge.lineage.child_depth == bridge.ingress_lease.child_depth
```

Reason codes:

```text
child_action_identity_mismatch
child_request_lease_mismatch
child_lineage_lease_mismatch
```

При несовпадении provider не вызывается, approval attempt не резервируется,
trusted facts/references не раскрываются, а child lease поглощается в outer
`finally` как failed invocation.

Root path выполняет bounded decode, coarse authorization и exact typed decode.
Child request строит только reviewed closed child-input builder, после чего
`_run_v2_internal` заново выполняет canonical lookup, ingress/principal,
mission/approval, facts/references/targets, readiness и policy.

After PR-7, `ChildExecutionFacadeV2.run_selected_child(spec)` is the only
router-visible entrypoint. Its executor-owned implementation creates the child
request/lease/bridge and then calls the overload above. Router, caller, planner
and plugin cannot receive/create/call `ChildExecutionBridge` or invoke the child
overload directly. AST/runtime gates allow the child overload call only inside
that facade implementation and executor tests.

### 4.9. Decision trace

Trace сохраняет только refs/revisions/digests:

```text
ingress session ref/revision
principal ref/revision
mission ref/revision
approval ref/revision
attempt group ID
approval graph and attempt-lease state event
root action ID
concrete action ID
stage/operation/target decision
```

Не сохранять API key, session token или authentication material.

## 5. Trusted facts и единый executor-owned target extraction

### 5.1. Raw facts запрещены в V2 request

V2 `ActionRequest` не принимает caller-supplied:

```python
facts: tuple[dict[str, Any], ...]
```

Он принимает только:

```python
precondition_fact_refs: tuple[str, ...]
```

V1 path сохраняет старое поле только для совместимости существующих 96 adapters.

### 5.2. `TrustedFactSnapshot`

Создать closed frozen DTO:

```python
@dataclass(frozen=True)
class TrustedFactSnapshot:
    schema_version: Literal["2.0"]
    fact_ref: str
    revision: int
    payload_digest: str
    mission_id: str
    target: str
    fact_type: TrustedFactType
    assessment_status: AssessmentStatus
    trust_level: TrustedFactTrustLevelV2
    freshness_status: FactFreshnessStatus
    coverage_status: EvidenceCoverageStatus
    source_execution_ids: tuple[str, ...]
    expires_at: float | None
```

Для action preconditions допускаются только:

```text
assessment_status == AssessmentStatus.VERIFIED
trust_level == TrustedFactTrustLevelV2.TRUSTED
freshness_status == FactFreshnessStatus.FRESH
coverage_status == EvidenceCoverageStatus.COMPLETE
UNKNOWN in trust/freshness/coverage → deny
mission_id совпадает
target входит в action targets
```

### 5.3. Closed decoder

Создать:

```python
class TrustedFactDecoder:
    def decode(
        self,
        stored_fact: StoredFactRecord,
        expected_ref: str,
    ) -> TrustedFactSnapshot: ...


def canonical_stored_fact_payload_digest(record: StoredFactRecord) -> str:
    """Digest schema octopus-trusted-fact/2.0, excluding payload_digest."""
    ...
```

Decoder:

```text
не принимает arbitrary dict от caller
разрешает только известные fact types
проверяет exact schema
отклоняет unknown/extra structural variants
проверяет fact_ref
проверяет revision
canonical-encodes the exact tagged fields
`schema_version,fact_ref,revision,mission_id,target,fact_type,assessment_status,
trust_level,freshness_status,coverage_status,source_execution_ids,expires_at`
and recomputes/compares payload_digest; payload_digest itself is excluded
не выводит raw value, если он не нужен policy
```

`FactCheckoutRequest.expected_payload_digest`, `TrustedFactSnapshot` and the
policy/decision-trace snapshot all carry that same digest. Final checkout
revalidates both revision and digest; a same-reference payload substitution is
therefore denied even if a corrupt store failed to advance its revision.
The helper uses RFC-8785 UTF-8 canonical JSON prefixed with
`octopus-trusted-fact/2.0\x00`; golden vectors and field-inclusion tests are
shared by decoder, checkout and decision-trace validation.

### 5.4. Executor-owned target extractor с PR-safe generic registry

PR-4 появляется раньше exact input DTO из PR-6 и поэтому не импортирует
`V2InputUnion`. Он создаёт generic infrastructure:

```python
TDecodedV2Input = TypeVar("TDecodedV2Input")


class ActionTargetExtractor(Protocol, Generic[TDecodedV2Input]):
    def extract(
        self,
        typed_input: TDecodedV2Input,
        reference_snapshots: tuple[ReferenceMetadataSnapshot, ...],
    ) -> tuple[ExtractedActionTarget, ...]: ...


class ActionTargetExtractorRegistry:
    def register(
        self,
        *,
        action_id: str,
        input_schema_id: str,
        input_type: type[TDecodedV2Input],
        extractor: ActionTargetExtractor[TDecodedV2Input],
    ) -> None: ...

    def extract_checked(
        self,
        *,
        action_id: str,
        input_schema_id: str,
        decoded_input: object,
        reference_snapshots: tuple[ReferenceMetadataSnapshot, ...],
    ) -> tuple[ExtractedActionTarget, ...]: ...
```

The private type-erased registry slot uses `object`, never `Any`, and must check
`type(decoded_input) is registered_input_type` before invoking the typed
extractor. PR-4 ships with zero V2 extractor registrations. PR-6 registers all
20 exact `(action_id, input_schema_id, input_type)` bindings from §2.4 and only
then introduces `V2InputUnion`.

Registry mapping after PR-6:

```text
RemoteForwardInputV2  → primary target + destination_host
SSHChainInputV2       → every hop target
PivotProxyScanInputV2 → scan target
RemoteExecInputV2     → target
Kerberos inputs       → target
C2DeployInputV3       → deployment target + session/channel/enrollment-bound targets
DNS channel input     → logical target + bind/listen endpoint role
```

Extractor returns only canonicalized `ExtractedActionTarget` from §5.5.
V2 targets cannot be obtained through:

```text
raw command parsing
adapter.invocation()
caller-supplied targets tuple
planner hints
```

Unknown action/schema, missing extractor, wrong runtime DTO type or ambiguous
canonicalization fails closed.

---

## 5.5. Canonical TargetScopePolicy

Заменить string-only target/scope представления на closed frozen модели:

```python
@dataclass(frozen=True)
class ExtractedActionTarget:
    role: TargetRole
    kind: TargetKind
    normalized_value: str
    port: int | None = None
    protocol: NetworkProtocol | None = None


@dataclass(frozen=True)
class TargetScopeRule:
    role: TargetRole | None
    kind: TargetKind
    normalized_value: str
    port: int | None = None
    protocol: NetworkProtocol | None = None
    allow_containment: bool = False


@dataclass(frozen=True)
class TargetScopeSnapshot:
    schema_version: str
    revision: int
    rules: tuple[TargetScopeRule, ...]
```

Canonical owner этих enums и scope DTO — `core/actions/target_scope.py`,
создаваемый в PR-4. PR-6 импортирует их и не определяет параллельные версии.

```python
class TargetRole(str, Enum):
    PRIMARY = "primary"
    DESTINATION = "destination"
    HOP = "hop"
    LISTEN = "listen"
    CALLBACK = "callback"
    RESOURCE_BOUND = "resource_bound"


class TargetKind(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    CIDR = "cidr"
    FQDN = "fqdn"
    HOST = "host"
    NETWORK_ENDPOINT = "network_endpoint"
    RESOURCE_BOUND_TARGET = "resource_bound_target"


class NetworkProtocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    DNS = "dns"
    HTTP = "http"
    HTTPS = "https"
    SSH = "ssh"
    SMB = "smb"
    WINRM = "winrm"
    DCOM = "dcom"
```

Неизвестное enum value, неоднозначный protocol или role вне закрытого набора
отклоняются decoder/canonicalizer до policy matching.

Создать единственного владельца canonicalization/matching:

```text
core/actions/target_scope.py

TargetScopeCanonicalizer
TargetScopePolicy
```

`TargetScopePolicy` обязан:

```text
canonicalize IPv4/IPv6/CIDR
нормализовать FQDN через IDNA и lowercase
различать primary, destination, hop, listen и callback roles
проверять port/protocol constraints
поддерживать resource-bound targets
запрещать prefix/suffix/substring matching
отклонять ambiguous host representations
использовать одинаковую семантику для mission, approval, facts и reference ACL
```

Canonical fields:

```text
MissionAuthorizationSnapshot.target_scope: TargetScopeSnapshot
ApprovalAuthorizationSnapshot.target_scope: TargetScopeSnapshot
ReferenceAuthorizationSnapshot.authorization_scope: TargetScopeSnapshot
ActionPolicyRequestSnapshot.targets: tuple[ExtractedActionTarget, ...]
ReferenceStore.checkout(...).targets: tuple[ExtractedActionTarget, ...]
```

Существующая scope-логика `ExecutionPolicy` мигрируется в `TargetScopePolicy` и не остаётся вторым matcher.

Добавить equivalence, IPv6, CIDR containment, FQDN/IDNA, port, protocol, resource-bound и target-role tests.

## 6. Frozen reference metadata и authorization snapshots

### 6.1. `ReferenceAuthorizationSnapshot`

```python
@dataclass(frozen=True)
class ReferenceAuthorizationSnapshot:
    schema_version: str
    reference: str
    authorization_revision: int

    mission_id: str
    owner_subject_id: str
    owner_subject_type: SubjectType

    permitted_subject_ids: tuple[str, ...]
    permitted_action_ids: tuple[str, ...]
    permitted_capabilities: tuple[str, ...]
    authorization_scope: TargetScopeSnapshot

    created_by_request_id: str
    delegated_by_subject_id: str | None
    expires_at: float | None
```

### 6.2. Metadata snapshots и closed union

```python
@dataclass(frozen=True)
class CredentialReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    target: str
    service: str
    username: str
    domain: str
    auth_kind: CredentialAuthKind
    port: int | None
    verified: bool
    expires_at: float | None


@dataclass(frozen=True)
class SessionReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    target: str
    service: str
    connected_peer: str
    state: SessionState
    created_at: float
    expires_at: float | None


@dataclass(frozen=True)
class SensitiveIntegrityTagV2:
    """PR-4 dependency-free keyed-integrity metadata; never a plaintext hash."""

    key_id: str
    algorithm: Literal["hmac-sha256-v2"]
    domain: str
    tag: str


@dataclass(frozen=True)
class NonSensitiveArtifactReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    artifact_kind: ArtifactKind
    target: str | None
    content_digest: str
    size: int
    media_type: str
    expires_at: float | None


@dataclass(frozen=True)
class SensitiveArtifactReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    artifact_kind: ArtifactKind
    target: str | None
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    size: int
    media_type: str
    expires_at: float | None


ArtifactReferenceSnapshot: TypeAlias = NonSensitiveArtifactReferenceSnapshot | SensitiveArtifactReferenceSnapshot


@dataclass(frozen=True)
class PivotRouteReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    session_ref: str
    source_fact_ref: str
    proxy_endpoint: ExtractedActionTarget
    allowed_scope: TargetScopeSnapshot
    state: RouteState
    expires_at: float | None


@dataclass(frozen=True)
class C2ReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    resource_kind: NonEnrollmentC2ResourceKindV2
    target: str | None
    daemon_instance_id: str | None
    state: C2ResourceState
    expires_at: float | None


# Added by PR-15 when EnrollmentLifecycleState/profile IDs exist. Enrollment is
# deliberately not represented by generic C2ResourceState.
@dataclass(frozen=True)
class EnrollmentReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    target: str
    channel_ref: str
    profile_id: C2DeploymentProfileId
    agent_protocol_version: Literal["12.0"]
    state: EnrollmentLifecycleState
    active_build_reservation_id: str | None
    max_uses: Literal[1]
    expires_at: float | None


@dataclass(frozen=True)
class DeploymentReferenceSnapshot:
    reference: str
    revision: int
    authorization: ReferenceAuthorizationSnapshot
    target: str
    lifecycle_owner: str
    state: DeploymentState
    deployment_attempt_id: str
    artifact_binding_digest: str
    expires_at: float | None


ReferenceMetadataSnapshot: TypeAlias = (
    CredentialReferenceSnapshot
    | SessionReferenceSnapshot
    | ArtifactReferenceSnapshot
    | PivotRouteReferenceSnapshot
    | C2ReferenceSnapshot
    | EnrollmentReferenceSnapshot
    | DeploymentReferenceSnapshot
)
```

Это единственный `ReferenceMetadataSnapshot` union. Open dict/`Any` snapshots
запрещены.

### 6.2A. Exact reference state enums и single ownership

PR-4 creates `core/actions/reference_types.py` as the single owner of state/kind
enums required by snapshots and material wrappers before later C2/deployment
modules exist:

```python
class SessionState(str, Enum):
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"
    EXPIRED = "expired"
    FAILED = "failed"


class ArtifactKind(str, Enum):
    GENERIC = "generic"
    PAYLOAD = "payload"
    PAYLOAD_LOADER = "payload_loader"
    KERBEROS_TICKET = "kerberos_ticket"
    WORDLIST = "wordlist"
    LSASS_DUMP = "lsass_dump"
    SAM_HIVE = "sam_hive"
    SYSTEM_HIVE = "system_hive"
    SECURITY_HIVE = "security_hive"
    C2_AGENT = "c2_agent"
    C2_REBIND_MANIFEST = "c2_rebind_manifest"
    TARGET_METADATA = "target_metadata"


class RouteState(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"
    EXPIRED = "expired"
    FAILED = "failed"


class C2ResourceKind(str, Enum):
    CHANNEL = "channel"
    AGENT = "agent"
    TASK = "task"


NonEnrollmentC2ResourceKindV2: TypeAlias = Literal[
    C2ResourceKind.CHANNEL,
    C2ResourceKind.AGENT,
    C2ResourceKind.TASK,
]


class C2ResourceState(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    CLOSED = "closed"
    FAILED = "failed"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"
    CANCELLED = "cancelled"


class DeploymentState(str, Enum):
    PREALLOCATED = "preallocated"
    BUILDING = "building"
    STAGED = "staged"
    UPLOADING = "uploading"
    START_DISPATCHING = "start_dispatching"
    ACTIVE = "active"
    IN_DOUBT = "in_doubt"
    CLEANING = "cleaning"
    CLOSED = "closed"
    ORPHANED = "orphaned"
    FAILED = "failed"
```

Current `CredentialRef.auth_kind` is a string field. PR-4 migrates it without
breaking stored/current V1 values by creating the single canonical enum in
`core/credentials.py`:

```python
class CredentialAuthKind(str, Enum):
    PASSWORD = "password"
    NT_HASH = "nt_hash"
    SSH_KEY = "ssh_key"
```

`CredentialRef.auth_kind` becomes `CredentialAuthKind`; the schema-versioned
legacy decoder accepts only the existing exact strings `password` and `ssh_key`
and the new exact string `nt_hash`. Unknown strings fail closed. Serialization
continues to emit the same string values, so existing password/SSH-key records
remain compatible while pass-the-hash gains a closed variant.

`core/sessions.py`, `core/artifacts.py`, `core/pivot_routes.py`,
`core/c2/resources.py` and later deployment modules import/re-export canonical
enums; they do not redefine them. Unknown stored values fail snapshot decoding
rather than becoming free-form strings.

### 6.3. Mandatory identity invariant

Executor обязательно проверяет:

```python
metadata_snapshot.reference == authorization_snapshot.reference
```

Несовпадение:

```text
reference_authorization_identity_mismatch
```

Проверка выполняется:

```text
при initial resolution
при atomic checkout
```

### 6.4. Остальные ACL checks

```text
mission binding
owner/permitted subject
permitted action
permitted capability
authorization scope
expiry
metadata revision
authorization revision
resource state
```

Snapshots не содержат:

```text
plaintext
secret refs
local paths
live handles
socket objects
transport objects
```

---

## 7. Atomic store-level checkout и lease fencing

### 7.1. Closed checkout request/bundle models

Все модели ниже принадлежат `core/actions/checkout_models.py` (PR-4):

```python
class ReferenceKind(str, Enum):
    CREDENTIAL = "credential"
    SESSION = "session"
    ARTIFACT = "artifact"
    PIVOT_ROUTE = "pivot_route"
    C2_RESOURCE = "c2_resource"
    C2_ENROLLMENT = "c2_enrollment"
    DEPLOYMENT = "deployment"


class ReferenceAccessMode(str, Enum):
    METADATA_ONLY = "metadata_only"
    MATERIAL = "material"


@dataclass(frozen=True)
class ReferenceCheckoutRequest:
    reference: str
    expected_kind: ReferenceKind
    expected_metadata_revision: int
    expected_authorization_revision: int
    required_action_id: str
    required_capability: str
    targets: tuple[ExtractedActionTarget, ...]
    access_mode: ReferenceAccessMode


@dataclass(frozen=True, repr=False)
class IngressSessionCheckoutRequest:
    lease_id: str
    lease_revision: int
    bound_request_id: str
    ingress_session_ref: str
    expected_session_revision: int
    principal_ref: str
    expected_principal_revision: int
    transport_instance_id: str
    transport_binding_digest: str


@dataclass(frozen=True)
class PrincipalCheckoutRequest:
    principal_ref: str
    expected_revision: int
    subject_id: str


@dataclass(frozen=True)
class MissionCheckoutRequest:
    mission_ref: str
    expected_revision: int
    subject_id: str


@dataclass(frozen=True, repr=False)
class ApprovalCheckoutRequest:
    approval_ref: str
    expected_revision: int
    approval_graph_lease_id: str
    execution_graph_id: str
    root_action_id: str
    concrete_action_id: str


@dataclass(frozen=True)
class FactCheckoutRequest:
    fact_ref: str
    expected_revision: int
    expected_payload_digest: str
    required_fact_type: str
    target: ExtractedActionTarget


@dataclass(frozen=True)
class ExecutionAttemptGroup:
    attempt_group_id: str
    root_execution_id: str
    execution_graph_id: str


@dataclass(frozen=True, repr=False)
class ExecutorCheckoutRequestBundle:
    references: tuple[ReferenceCheckoutRequest, ...]
    ingress_session: IngressSessionCheckoutRequest
    principal: PrincipalCheckoutRequest
    mission: MissionCheckoutRequest
    approval: ApprovalCheckoutRequest | None
    facts: tuple[FactCheckoutRequest, ...]
    targets: tuple[ExtractedActionTarget, ...]
    attempt_group: ExecutionAttemptGroup
```

Единственное имя ingress checkout DTO — `IngressSessionCheckoutRequest`.
Сокращённого альтернативного ingress-checkout DTO не существует.

Material checkout handles and provider views belong only to
`core/actions/materials.py`. They are deliberately split. PR-4 creates the
executor-only checkout side; PR-5 modifies the module after phase-lease and
zeroizable foundations exist and adds the provider side. No checkout cleanup
method is ever reachable from a provider.

PR-4 exact executor-only surface:

```python
@runtime_checkable
class ExecutorCheckoutHandleV2(Protocol):
    @property
    def checkout_id(self) -> str: ...
    def close_checkout(self) -> None: ...


@dataclass(frozen=True, repr=False)
class ExecutorOpenedMaterialV2:
    reference: str
    reference_kind: ReferenceKind
    checkout_id: str
    metadata: ReferenceMetadataSnapshot
    checkout_handle: ExecutorCheckoutHandleV2 = field(repr=False, compare=False)


@dataclass(frozen=True, repr=False)
class ExecutorOpenedMaterialBundleV2:
    checkout_id: str
    materials: tuple[ExecutorOpenedMaterialV2, ...]
```

`ExecutorOpenedMaterialBundleV2` never crosses the provider boundary. PR-5
adds the final, read-only provider view family:

```python
@runtime_checkable
class ProviderMaterialViewV2(Protocol):
    @property
    def checkout_id(self) -> str: ...
    @property
    def provider_handle_id(self) -> str: ...
    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2: ...


@runtime_checkable
class PhaseBoundSensitiveBufferLeaseV2(Protocol):
    """Provider-only lease; every read is serialized with phase revocation."""

    @property
    def lease_id(self) -> str: ...
    @property
    def byte_length(self) -> int: ...
    def read_into(self, destination: ZeroizableDestinationBufferV2) -> int: ...
    def close_and_zeroize(self) -> None: ...


@runtime_checkable
class ProviderCredentialSecretViewV2(ProviderMaterialViewV2, Protocol):
    def acquire_single_use(
        self,
        *,
        consumer_id: str,
    ) -> PhaseBoundSensitiveBufferLeaseV2: ...


@dataclass(frozen=True)
class RemoteForwardOpenRequestV2:
    destination: ExtractedActionTarget
    local_bind: ExtractedActionTarget
    absolute_deadline_monotonic: float


@dataclass(frozen=True)
class RouteStreamOpenRequestV2:
    destination: ExtractedActionTarget
    absolute_deadline_monotonic: float


@runtime_checkable
class PhaseBoundStreamV2(Protocol):
    @property
    def transient_ref(self) -> PhaseBoundTransientRefV2: ...
    def send_view(self, data: memoryview) -> int: ...
    def receive_into(self, destination: bytearray) -> int: ...


@runtime_checkable
class ProviderSessionViewV2(ProviderMaterialViewV2, Protocol):
    def open_remote_forward(
        self,
        request: RemoteForwardOpenRequestV2,
    ) -> PhaseBoundTransientRefV2: ...


@runtime_checkable
class NonSensitiveArtifactReadViewV2(ProviderMaterialViewV2, Protocol):
    def read_bytes(self, *, max_bytes: int) -> bytes: ...


@runtime_checkable
class SensitiveArtifactReadViewV2(ProviderMaterialViewV2, Protocol):
    def acquire_single_use(
        self,
        *,
        consumer_id: str,
    ) -> PhaseBoundSensitiveBufferLeaseV2: ...


@runtime_checkable
class ProviderPivotRouteViewV2(ProviderMaterialViewV2, Protocol):
    def open_stream(self, request: RouteStreamOpenRequestV2) -> PhaseBoundStreamV2: ...


@dataclass(frozen=True, repr=False)
class BoundCredentialMaterial:
    reference: str
    checkout_id: str
    target: str
    service: str
    username: str
    domain: str
    auth_kind: CredentialAuthKind
    port: int | None
    secret: ProviderCredentialSecretViewV2 = field(repr=False, compare=False)


@dataclass(frozen=True, repr=False)
class BoundSessionMaterial:
    reference: str
    checkout_id: str
    target: str
    service: str
    connected_peer: str
    handle: ProviderSessionViewV2 = field(repr=False, compare=False)


@dataclass(frozen=True, repr=False)
class BoundNonSensitiveArtifactMaterial:
    reference: str
    checkout_id: str
    artifact_kind: ArtifactKind
    content_digest: str
    size: int
    media_type: str
    target: str | None
    handle: NonSensitiveArtifactReadViewV2 = field(repr=False, compare=False)


@dataclass(frozen=True, repr=False)
class BoundSensitiveArtifactMaterial:
    reference: str
    checkout_id: str
    artifact_kind: ArtifactKind
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    size: int
    media_type: str
    target: str | None
    handle: SensitiveArtifactReadViewV2 = field(repr=False, compare=False)


@dataclass(frozen=True, repr=False)
class BoundPivotRouteMaterial:
    reference: str
    checkout_id: str
    session_ref: str
    proxy_endpoint: ExtractedActionTarget
    allowed_scope: TargetScopeSnapshot
    handle: ProviderPivotRouteViewV2 = field(repr=False, compare=False)


@dataclass(frozen=True, repr=False)
class BoundC2ResourceMaterial:
    reference: str
    checkout_id: str
    resource_kind: NonEnrollmentC2ResourceKindV2
    state: C2ResourceState
    target: str | None
    daemon_instance_id: str | None


@dataclass(frozen=True, repr=False)
class BoundEnrollmentMaterial:
    reference: str
    checkout_id: str
    revision: int
    state: EnrollmentLifecycleState
    channel_ref: str
    target: str
    profile_id: C2DeploymentProfileId
    deployment_reservation: BoundDeploymentReservationV1
    build_material: EnrollmentBuildMaterialViewV1 = field(repr=False, compare=False)


@dataclass(frozen=True, repr=False)
class BoundDeploymentMaterial:
    reference: str
    checkout_id: str
    state: DeploymentState
    target: str
    lifecycle_owner: str
    deployment_attempt_id: str
    artifact_binding_digest: str


BoundMaterial: TypeAlias = (
    BoundCredentialMaterial
    | BoundSessionMaterial
    | BoundNonSensitiveArtifactMaterial
    | BoundSensitiveArtifactMaterial
    | BoundPivotRouteMaterial
    | BoundC2ResourceMaterial
    | BoundEnrollmentMaterial
    | BoundDeploymentMaterial
)


@dataclass(frozen=True, repr=False)
class BoundMaterialBundle:
    checkout_id: str
    materials: tuple[BoundMaterial, ...]


class ProviderMaterialBinderV2(Protocol):
    def bind(
        self,
        opened: ExecutorOpenedMaterialBundleV2,
        phase_lease: ProviderExecutePhaseLeaseV2,
        *,
        _phase_controller: _ProviderExecutePhaseLeaseControllerV2,
    ) -> BoundMaterialBundle: ...
```

Every provider-view method first calls `phase_lease.require_active()`. Provider
views expose no `close*`, `clear`, `transfer`, store, checkout or raw backend
object. The binder retains the executor-handle mapping privately; revocation
makes cached views inert, while executor cleanup can close the underlying
checkout handles after revocation. Immutable `bytes` are available only on the
explicit non-sensitive artifact branch. A sensitive artifact can be read only
through a bounded zeroizable single-use lease.

`PhaseBoundSensitiveBufferLeaseV2` is distinct from executor-internal secret/
buffer leases. Acquisition registers it with the phase controller; every read
holds the controller's shared revocation lock. `revoke()` atomically prevents
new reads and closes/zeroizes all outstanding provider leases before returning,
so caching a lease cannot extend material access past execute. Session/route
operations use similarly phase-bound reviewed methods; their returned stream/
transient views are immediately registered with the restricted scope and become
inert on revoke or transfer. Metadata-only C2/deployment wrappers intentionally
carry no live handle. Providers may not downcast to executor handles or import a
raw backend object.
The binder requires `_phase_controller.view is phase_lease` and passes the
private controller only into core concrete view implementations so they can
register child sensitive leases and transient views. The controller is never
stored in or returned through `BoundMaterialBundle`.

PR-4 initially creates the unions without enrollment-specific symbols. PR-15
atomically modifies `reference_snapshots.py`, `checkout_models.py` and
`materials.py` after creating `EnrollmentLifecycleState`, then adds
`EnrollmentReferenceSnapshot`, `ReferenceKind.C2_ENROLLMENT` and
`BoundEnrollmentMaterial`. Generic `C2ReferenceSnapshot` is thereafter limited
to CHANNEL/AGENT/TASK; decoding ENROLLMENT through it fails closed.
For `c2_deploy`, `ReferenceCheckoutCoordinator.open_materials()` performs the
daemon reservation and keeps the private `EnrollmentBuildCheckout` in the
executor-only opened bundle. `ProviderMaterialBinderV2` creates only a
phase-bound `EnrollmentBuildMaterialViewV1` inside `BoundEnrollmentMaterial`.
Provider code has no C2 client, release or transfer API. The reservation and
approval attempt start are fenced
by an ordered recovery protocol, not falsely claimed atomic across processes:
reserve enrollment first, then start the approval attempt; a crash before
STARTED releases/revokes the orphan reservation, while a crash after STARTED
never refunds the approval use and reconciles according to exposure state.

Mandatory bundle invariants:

```text
- every wrapper checkout_id equals bundle.checkout_id;
- each reference occurs at most once;
- wrapper runtime type must match the requested ReferenceKind;
- handle fields are excluded from repr/equality/audit/pickle/JSON;
- wrappers never own lifecycle resources independently of checkout/scope;
- every material/temp handle remains owned by the fenced checkout until checkout close;
- provider-created transients introduced from PR-5 onward are separately owned by `InvocationScope`;
- checkout closes every checkout-bound handle exactly once on every exit path.
```

### 7.2. Two-phase fenced checkout: snapshots first, material only after final readiness

Каждый store сначала реализует snapshot/lease checkout без material reveal:

```python
class ReferenceStore(Protocol):
    def checkout(
        self,
        *,
        reference: str,
        expected_metadata_revision: int,
        expected_authorization_revision: int,
        ingress_session: IngressSessionAuthorizationSnapshot,
        mission: MissionAuthorizationSnapshot,
        action_id: str,
        targets: tuple[ExtractedActionTarget, ...],
    ) -> ReferenceCheckout: ...
```

Одна store transaction/lock выполняет в указанном порядке:

```text
load current metadata
load current authorization
check metadata.reference == authorization.reference
check metadata revision
check authorization revision
check ACTIVE state and expiry
check ingress subject/mission/action/capability/scope ACL
create fenced checkout lease
return immutable metadata + lease token
open no secret/live material
```

Нельзя делать:

```text
resolve material during initial checkout
→ run readiness afterward
```

After successful `check_bound`, PENDING approval reservation and final readiness,
`ReferenceCheckoutCoordinator.open_materials(...)` reacquires every participating
store in canonical lock order, revalidates metadata/authorization/fact/approval
revisions and fence generations, and opens all requested materials atomically.
If any revalidation or open fails, it closes every partially opened handle and
returns no `ExecutorOpenedMaterialBundleV2`. The executor binds provider views
with the already-created inactive phase lease; no view is usable until the
provider boundary activates that lease. Thus material reveal occurs after
readiness but still inside one all-or-nothing fenced store operation.

Only `ReferenceCheckoutRequest(access_mode=MATERIAL)` entries produce wrappers.
`METADATA_ONLY` references remain fenced snapshots and are revalidated but never
opened. In particular c2_task agent refs and c2_cleanup resource refs are
metadata-only; c2_deploy enrollment uses MATERIAL because the coordinator must
create the build reservation. Access mode is derived by the per-action reference
schema and cannot be caller-selected.

### 7.3. Fenced lease

`ReferenceCheckout` содержит:

```python
@dataclass(frozen=True)
class ReferenceLeaseToken:
    reference: str
    metadata_revision: int
    authorization_revision: int
    fence_generation: int
    checkout_id: str
```

Store гарантирует до close checkout:

```text
resource cannot be replaced without fence invalidation
material belongs only to checkout
state-changing operations detect active lease/fence
```

Перед invocation coordinator выполняет:

```python
checkout_bundle.assert_current()
```

### 7.4. Multi-reference checkout

```python
@dataclass(frozen=True, repr=False)
class ReferenceCheckout:
    metadata: ReferenceMetadataSnapshot
    lease_token: ReferenceLeaseToken


@dataclass(frozen=True, repr=False)
class ExecutorCheckoutBundle:
    checkout_id: str
    ingress_session: IngressSessionAuthorizationSnapshot
    principal: PrincipalAuthorizationSnapshot
    mission: MissionAuthorizationSnapshot
    approval_graph_lease: ApprovalExecutionLease | None
    facts: tuple[TrustedFactSnapshot, ...]
    references: tuple[ReferenceCheckout, ...]
    targets: tuple[ExtractedActionTarget, ...]
    fence_generation: int

    def assert_current(self) -> None: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class CheckoutRecoveryRefV2:
    checkout_id: str
    fence_generation: int
    journal_ref: str
    journal_digest: str


class ReferenceCheckoutCoordinator:
    def checkout_many(
        self,
        request: ExecutorCheckoutRequestBundle,
    ) -> ExecutorCheckoutBundle: ...

    def open_materials(
        self,
        checkout: ExecutorCheckoutBundle,
    ) -> ExecutorOpenedMaterialBundleV2: ...

    def checkpoint_existing_recovery_state(
        self,
        checkout: ExecutorCheckoutBundle,
        current_ref: CheckoutRecoveryRefV2,
    ) -> CheckoutRecoveryRefV2: ...

    def reopen_fenced(
        self,
        recovery_ref: CheckoutRecoveryRefV2,
    ) -> ExecutorCheckoutBundle: ...


@runtime_checkable
class ReferenceCheckoutRecoveryStoreV2(Protocol):
    def require(
        self,
        recovery_ref: CheckoutRecoveryRefV2,
    ) -> CheckoutRecoveryRefV2: ...
    def close_reopened(
        self,
        recovery_ref: CheckoutRecoveryRefV2,
        operation: CleanupOperationContextV2,
    ) -> RecoveryOwnerCleanupReceiptV2: ...
```

`ReferenceCheckoutRecoveryStoreV2` and `close_reopened()` are PR-5 MODIFY
additions to the PR-4 checkout module. They are absent from the independently
type-checked PR-4 tree, which therefore imports neither
`CleanupOperationContextV2` nor `RecoveryOwnerCleanupReceiptV2` from the future.

Coordinator:

```text
uses canonical lock order
checks ingress/principal identity invariant
checks mission membership
validates approval graph lease/revision; does not reserve a concrete attempt
checks trusted fact revisions
checks all reference revisions and ACLs
opens no material until every checkout can succeed
returns immutable snapshots + fenced leases; after final readiness, material opens only through coordinator-owned `open_materials(checkout_bundle)`
releases all leases on failure
```

`ExecutorCheckoutBundle` intentionally has no `open_materials`, `reveal`, store
or raw-handle method. Only `ReferenceCheckoutCoordinator.open_materials(...)`
can perform the second fenced transaction. An AST ratchet enforces this surface.
PR-4 exposes `checkout_many()` only as a dormant independently tested helper.
PR-5 makes its production entry factory-token-private: the executor calls only
`IntentBoundCheckoutOwnerFactoryV2.reserve_inert()` → full intent checkpoint →
`activate_after_intent_checkpoint()`, whose implementation invokes
`checkout_many()`. Direct executor checkout construction/calls are forbidden;
`open_materials()` remains the post-readiness second transaction on the already
intent-attached bundle.

### 7.5. Trusted facts and approval included

Final checkout validates:

```text
ingress session revision/peer binding
principal revision
mission revision
approval graph lease/revision; concrete attempt is not reserved yet
trusted fact revisions
metadata revisions
authorization revisions
resource state
```

### 7.6. Pending attempt reservation и immediate readiness recheck

Execution order after checkout:

```text
checkout_bundle.assert_current()
attempt_ref = attempt_factory.reserve_inert(
    intent=current_intent,
    creation_spec=attempt_creation_spec,
    creation_spec_digest=attempt_creation_spec.spec_digest,
)
current_intent = intent_store.checkpoint(..., attempt_recovery_ref=attempt_ref)
attempt_lease = attempt_factory.activate_after_intent_checkpoint(
    intent=current_intent,
    recovery_ref=attempt_ref,
)  # PENDING, use ещё не списан
fresh_readiness = readiness_registry.recheck(...)
checkout_bundle.assert_current()

if not fresh_readiness.available:
    attempt_lease.release_before_start()
    outcome = UNAVAILABLE
else:
    phase_controller = _ProviderExecutePhaseLeaseControllerV2()
    opened_bundle = checkout_coordinator.open_materials(checkout_bundle)
    material_bundle = material_binder.bind(
        opened_bundle,
        phase_controller.view,
        _phase_controller=phase_controller,
    )
    checkout_bundle.assert_current()
    readiness_registry.assert_current(fresh_readiness)
    attempt_lease.start()  # атомарно PENDING → STARTED и списывает use
    provider boundary activates phase_controller and invokes with material_bundle
```

Reservation создаётся до final readiness recheck, чтобы один approval budget
нельзя было одновременно зарезервировать несколькими concrete leaves. Полный
readiness probe выполняется после atomic snapshot/reference checkout и
intent-bound PENDING reservation, а generation/identity assertion того же snapshot повторяется
после material open непосредственно перед `start()`; mismatch закрывает opened
bundle и освобождает PENDING lease без списания use.

Если unavailable:

```text
provider not invoked
PENDING attempt lease выполняет release_before_start()
approval use не расходуется
checkout closes
InvocationScope finally runs
outcome=UNAVAILABLE
```

## 8. Guaranteed cleanup и unified execution commit coordinator

### 8.1. `InvocationScope`

The following is one logical cleanup surface with exact physical ownership.
`core/actions/invocation_scope.py` owns `CleanupCallback`, cleanup descriptors,
handler status/receipt/registry contracts, transient/scope ownership and the
scope implementation; it imports `CleanupStatusV2` and
`CleanupErrorSummaryV2` from PR-2. Dependency-light
`InvocationScopeRecoveryRefV2` is owned only by
`core/actions/execution_recovery_types.py`. `CleanupOperationContextV2`, its
subject/policy, the authority Protocol and final concrete authority are owned
only by `core/actions/cleanup_operation_context.py`. These modules import in
that direction and never redeclare a symbol shown in the logical block:

```python
CleanupCallback: TypeAlias = Callable[[], None]  # executor-internal, never provider supplied


class CleanupDescriptorKindV2(str, Enum):
    CLOSE_TRANSIENT = "close_transient"
    RELEASE_CHECKOUT = "release_checkout"
    RELEASE_RESERVATION = "release_reservation"
    CLOSE_LOCAL_IPC = "close_local_ipc"


@dataclass(frozen=True)
class RecoverableCleanupDescriptorV2:
    cleanup_id: str
    kind: CleanupDescriptorKindV2
    registry_id: str
    resource_ref: str
    expected_revision: int | None
    idempotency_key: str
    descriptor_digest: str


@dataclass(frozen=True)
class InvocationScopeRecoveryRefV2:
    scope_id: str
    revision: int
    journal_ref: str
    journal_digest: str


class CleanupHandlerStatusV2(str, Enum):
    SUCCEEDED = "succeeded"
    ALREADY_CLEAN = "already_clean"
    RETRYABLE = "retryable"
    FAILED = "failed"


@dataclass(frozen=True)
class CleanupHandlerReceiptV2:
    cleanup_id: str
    idempotency_key: str
    descriptor_digest: str
    status: CleanupHandlerStatusV2
    receipt_ref: str
    receipt_digest: str


@dataclass(frozen=True, repr=False)
class CleanupOperationContextV2:
    operation_attempt_id: str
    subject_digest: str
    authority_revision: int
    issued_at_monotonic: float
    absolute_deadline_monotonic: float
    retry_policy: ParticipantRetryPolicyV2
    authority_digest: str
    cancellation: CancellationToken = field(repr=False, compare=False)


@dataclass(frozen=True)
class CleanupRecoverySubjectV2:
    owner_kind: str
    owner_reference: str
    owner_revision: int
    idempotency_key: str
    subject_digest: str


@dataclass(frozen=True)
class CleanupRecoveryPolicyV2:
    policy_id: str
    max_attempts: int
    total_budget_ms: int
    per_attempt_deadline_ms: int
    policy_digest: str


@runtime_checkable
class CleanupOperationAuthorityV2(Protocol):
    def issue_live(
        self,
        *,
        subject: CleanupRecoverySubjectV2,
        operation_attempt_id: str,
        controller: ExecutorCancellationController,
        policy: CleanupRecoveryPolicyV2,
    ) -> CleanupOperationContextV2: ...
    def issue_recovery(
        self,
        *,
        subject: CleanupRecoverySubjectV2,
        operation_attempt_id: str,
        policy: CleanupRecoveryPolicyV2,
    ) -> CleanupOperationContextV2: ...
    def validate(
        self,
        context: CleanupOperationContextV2,
        *,
        subject: CleanupRecoverySubjectV2,
    ) -> None: ...


class _CleanupOperationAuthorityConstructionTokenV2:
    """Module-private bootstrap token; never exported or decoded."""


@final
class OwnedCleanupOperationAuthorityV2:
    """Sole production CleanupOperationContextV2 issuer and validator."""

    _construction_token: _CleanupOperationAuthorityConstructionTokenV2
    _maximum_policy: CleanupRecoveryPolicyV2
    _authority_revision: int
    _recovery_controllers: dict[str, ExecutorCancellationController]

    def __init__(
        self,
        *,
        maximum_policy: CleanupRecoveryPolicyV2,
        _construction_token: _CleanupOperationAuthorityConstructionTokenV2,
    ) -> None: ...

    def issue_live(
        self,
        *,
        subject: CleanupRecoverySubjectV2,
        operation_attempt_id: str,
        controller: ExecutorCancellationController,
        policy: CleanupRecoveryPolicyV2,
    ) -> CleanupOperationContextV2: ...

    def issue_recovery(
        self,
        *,
        subject: CleanupRecoverySubjectV2,
        operation_attempt_id: str,
        policy: CleanupRecoveryPolicyV2,
    ) -> CleanupOperationContextV2: ...

    def validate(
        self,
        context: CleanupOperationContextV2,
        *,
        subject: CleanupRecoverySubjectV2,
    ) -> None: ...


@runtime_checkable
class RecoverableCleanupHandlerV2(Protocol):
    def cleanup(
        self,
        descriptor: RecoverableCleanupDescriptorV2,
        operation: CleanupOperationContextV2,
    ) -> CleanupHandlerReceiptV2: ...


@runtime_checkable
class RecoverableCleanupRegistryV2(Protocol):
    def require_handler(
        self,
        *,
        kind: CleanupDescriptorKindV2,
        registry_id: str,
    ) -> RecoverableCleanupHandlerV2: ...


@runtime_checkable
class TransientResource(Protocol):
    @property
    def transient_id(self) -> str: ...
    @property
    def closed(self) -> bool: ...
    def close(self) -> None: ...


@runtime_checkable
class ArtifactTransientSinkV2(Protocol):
    def write_view(self, chunk: memoryview) -> None: ...


@runtime_checkable
class ReadableArtifactTransientV2(TransientResource, Protocol):
    """Artifact transient readable only by the executor-private staging sink."""

    @property
    def byte_length(self) -> int: ...
    def stream_into(self, sink: ArtifactTransientSinkV2) -> None: ...


@runtime_checkable
class ArtifactTransientResolverV2(Protocol):
    def claim_owned_for_staging(
        self,
        *,
        scope: InvocationScope,
        transient_id: str,
    ) -> ReadableArtifactTransientV2: ...


@runtime_checkable
class ResourceOwner(Protocol):
    @property
    def owner_id(self) -> str: ...
    def accept_transient(
        self,
        transient_id: str,
        resource: TransientResource,
    ) -> None: ...


@dataclass(frozen=True)
class InvocationCleanupResult:
    status: CleanupStatusV2
    callbacks_run: int
    resources_closed: int
    errors: tuple[CleanupErrorSummaryV2, ...] = ()


class InvocationScope:
    def add_internal_cleanup(
        self,
        callback: CleanupCallback,
        *,
        recovery: RecoverableCleanupDescriptorV2 | None,
    ) -> None: ...
    def own_transient(
        self,
        resource: TransientResource,
        *,
        recovery: RecoverableCleanupDescriptorV2,
    ) -> str: ...
    def transfer(
        self,
        transient_id: str,
        new_owner: ResourceOwner,
    ) -> TransientResource: ...
    def checkpoint_existing_recovery_state(
        self,
        current_ref: InvocationScopeRecoveryRefV2,
    ) -> InvocationScopeRecoveryRefV2: ...
    def close(self) -> InvocationCleanupResult: ...


@runtime_checkable
class InvocationScopeRecoveryStoreV2(Protocol):
    def reopen(
        self,
        recovery_ref: InvocationScopeRecoveryRefV2,
        cleanup_registry: RecoverableCleanupRegistryV2,
        operation: CleanupOperationContextV2,
    ) -> InvocationScope: ...
    def close_reopened(
        self,
        recovery_ref: InvocationScopeRecoveryRefV2,
        cleanup_registry: RecoverableCleanupRegistryV2,
        operation: CleanupOperationContextV2,
    ) -> RecoveryOwnerCleanupReceiptV2: ...


class ProviderTransientKindV2(str, Enum):
    ARTIFACT = "artifact"
    REMOTE_FORWARD = "remote_forward"
    ROUTE_STREAM = "route_stream"
    PROCESS = "process"
    TEMPORARY_FILE = "temporary_file"


class OwnedTransientStateV2(str, Enum):
    SCOPE_OWNED = "scope_owned"
    TRANSFERRED = "transferred"
    CLOSED = "closed"


@dataclass(frozen=True)
class BackendOwnedTransientReceiptV2:
    backend_registry_id: str
    backend_handle_ref: str
    transient_kind: ProviderTransientKindV2
    cleanup_descriptor: RecoverableCleanupDescriptorV2
    receipt_digest: str


@dataclass(frozen=True)
class ProviderTransientRegistrationV2:
    creation_receipt: BackendOwnedTransientReceiptV2


class PhaseBoundTransientRefV2:
    """Final provider view; no raw backend handle or public constructor."""

    @property
    def transient_id(self) -> str: ...
    @property
    def transient_kind(self) -> ProviderTransientKindV2: ...
    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2: ...
    def require_active(self) -> None: ...


class OwnedTransientV2:
    """Executor-only move-once capsule stored in OwnedTransientRegistryV2."""

    transient_id: str
    transient_kind: ProviderTransientKindV2
    state: OwnedTransientStateV2
    cleanup_descriptor: RecoverableCleanupDescriptorV2


@runtime_checkable
class OwnedTransientRegistryV2(Protocol):
    def claim_backend_receipt(
        self,
        *,
        scope_id: str,
        receipt: BackendOwnedTransientReceiptV2,
        phase_controller: _ProviderExecutePhaseLeaseControllerV2,
    ) -> PhaseBoundTransientRefV2: ...
    def transfer_to_owner(
        self,
        *,
        transient_id: str,
        owner: ResourceOwner,
    ) -> None: ...
    def reopen_owned(self, transient_id: str) -> OwnedTransientV2: ...


class ProviderPhaseLeaseStateV2(str, Enum):
    PENDING = "pending"
    ACTIVE = "active"
    REVOKED = "revoked"


class ProviderExecutePhaseLeaseV2:
    """Read-only capability view; providers cannot change its state."""

    @property
    def state(self) -> ProviderPhaseLeaseStateV2: ...
    @property
    def active(self) -> bool: ...
    def require_active(self) -> None: ...


class _ProviderExecutePhaseLeaseControllerV2:
    """Executor-only monotonic PENDING -> ACTIVE -> REVOKED controller."""

    @property
    def view(self) -> ProviderExecutePhaseLeaseV2: ...
    def bind_sensitive_lease(
        self,
        lease: ZeroizableSensitiveBufferLeaseV2,
    ) -> PhaseBoundSensitiveBufferLeaseV2: ...
    def register_transient_view(self, view: PhaseBoundTransientRefV2) -> None: ...
    def activate(self) -> None: ...
    def revoke(self) -> None: ...


@runtime_checkable
class ProviderInvocationScopeV2(Protocol):
    """Provider-visible view: closed resource descriptors only."""

    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2: ...
    def register_transient(
        self,
        request: ProviderTransientRegistrationV2,
    ) -> PhaseBoundTransientRefV2: ...
```

`CleanupOperationContextV2` has no public constructor in production. PR-5's
executor-owned final `OwnedCleanupOperationAuthorityV2`, created only by the
module-private bootstrap token and exposed to consumers through
`CleanupOperationAuthorityV2`, is its sole minting seam. Every
recovery store/handler validates the authority and subject digest before I/O.
`issue_live()` derives the token from the exact executor controller.
`issue_recovery()` creates and binds a new current-process recovery controller
and computes a fresh `time.monotonic()` deadline from the bounded persisted
policy; it never deserializes or reuses the original process's token or
monotonic timestamp. Attempt/idempotency identity is stable, while each retry
has a new authority revision/digest. Forged, expired, over-budget or wrong-owner
contexts fail before cleanup I/O.
The startup `ExecutionReconcilerV2` receives that exact owned authority by
constructor injection. For every recovery attempt it uses `issue_recovery()`,
which allocates a private per-attempt `ExecutorCancellationController`, clamps
the checked-in policy to the configured maximum, records the authority revision
and disposes the controller after the bounded operation. No ambient registry,
caller-supplied token/clock or pre-restart context is accepted.

`transfer()` first calls `new_owner.accept_transient(...)` and only then removes
the resource from scope ownership. If acceptance fails, ownership remains with
the scope. `close()` is idempotent and never raises; failures are returned in
`InvocationCleanupResult`.

Properties:

```text
idempotent close
LIFO cleanup
each callback at most once
cleanup errors aggregated
primary outcome preserved
```

`InvocationScope` and `ResourceOwner` are private executor surfaces. Providers
and C2 builders receive only `ProviderInvocationScopeV2`; it exposes neither
`add_cleanup`, `transfer`, `close`, a raw handle nor `ResourceOwner`, so a
provider cannot arrange post-boundary callback execution, invent an owner or
escape cleanup. `ProviderTransientRegistrationV2` is a closed union of reviewed
backend/resource descriptors. The core registry creates final
`OwnedTransientV2` capsules; providers receive only a phase-bound ID/view.
Transfer atomically invalidates that view and moves a distinct private handle to
the lifecycle owner. Custom structural resources, lambdas/callables and cached
raw handles are rejected by type, runtime and provider-import ratchets.
Core-private callable cleanup is permitted only when paired with a closed
recoverable descriptor. A scope with an unjournaled callback cannot detach; the
executor retains it in the emergency live-owner registry and returns no report
until quiescence. `checkpoint_existing_recovery_state()` CASes only newly added
closed descriptors into the scope's already intent-attached recovery record; it
never creates a second detach authority or serializes Python callables. Startup
reopens those descriptors through the named cleanup
registry. Unknown kind/registry, descriptor-digest mismatch or a non-idempotent
receipt keeps finalization pending and never dispatches an open global handler.

Reviewed backend workers return only `BackendOwnedTransientReceiptV2`; the
executor registry owns the actual handle. `ProviderInvocationScopeV2.register_transient()`
claims that receipt exactly once and returns a phase-bound ref. Session/route
material methods perform this same registration internally and directly return
the registered ref/stream; callers must not register those a second time.
Staging transfers the registry capsule atomically, invalidates every provider
view and gives the lifecycle owner a distinct private handle. Retaining a
receipt, view or former backend object cannot operate or close the transferred
resource.
The executor constructs one controller and its PENDING view before opening any
material, then binds that exact view into every provider-visible scope, material
view, staging facade and participant facade. PENDING access fails closed.
`ProviderCallBoundary` only activates immediately before calling provider code
and revokes in its own `finally` on return/exception/timeout/cancellation before
normalization or verify. Cached capabilities then fail closed even when an
adapter retains them on `self`. The controller never crosses the boundary.

### 8.2. Executor-owned commit coordinator, closed participant registration and finalization fence

A provider never receives `ExecutionCommitCoordinator` or a concrete
`ExecutionCommitParticipant`. It receives only restricted staging and
participant-registration capabilities.

Canonical participant types are created in PR-5. The dependency-free
`core/actions/execution_commit_types.py` solely owns `ExecutionCommitStateV2`,
`ExecutionCommitDecisionBindingV2`, its canonical binding-digest helper and
`ExecutionCommitRecordV2`; both commit/recovery modules import them, so the
light fence validation receipt does not introduce a recovery→commit→recovery
cycle. Participant enums, lifecycle DTOs/protocols and coordinator behavior
remain in `execution_commit.py`:

```python
class ParticipantKindV2(str, Enum):
    LOCAL_STORE = "local_store"
    MANAGED_RESOURCE = "managed_resource"
    CROSS_PROCESS_RESOURCE = "cross_process_resource"
    CROSS_PROCESS_CONTROL = "cross_process_control"
    EXTERNAL_EFFECT = "external_effect"
    EXECUTION_RESULT = "execution_result"
    AUDIT_OUTBOX = "audit_outbox"


class ParticipantStateV2(str, Enum):
    REGISTERED = "registered"
    PREPARED = "prepared"
    IN_DOUBT = "in_doubt"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED = "finalized"
    ROLLED_BACK = "rolled_back"
    ABORTED_UNPREPARED = "aborted_unprepared"
    RECONCILIATION_FAILED = "reconciliation_failed"


class ParticipantVisibilityModeV2(str, Enum):
    COORDINATOR_FENCE = "coordinator_fence"
    EXPLICIT_FINALIZE = "explicit_finalize"


class ExecutionCommitStateV2(str, Enum):
    OPEN = "open"
    PREPARING = "preparing"
    PREPARED = "prepared"
    IN_DOUBT = "in_doubt"
    ABORT_DECIDED = "abort_decided"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    COMMIT_DECIDED = "commit_decided"
    COMMITTING = "committing"
    COMMIT_APPLIED = "commit_applied"
    FINALIZING_VISIBILITY = "finalizing_visibility"
    COMMITTED = "committed"
    FAILED_RECONCILIATION = "failed_reconciliation"


@dataclass(frozen=True)
class ExecutionCommitDecisionBindingV2:
    no_return_admission_reference: str
    no_return_admission_revision: int
    no_return_admission_digest: str
    decision_identity_digest: str
    external_effect_participant_id: str | None
    external_effect_registration_digest: str | None
    binding_digest: str

    def __post_init__(self) -> None:
        if (self.external_effect_participant_id is None) != (self.external_effect_registration_digest is None):
            raise ValueError("commit_effect_binding_fields_all_or_none")
        if self.binding_digest != canonical_execution_commit_decision_binding_digest(self):
            raise ValueError("commit_decision_binding_digest_mismatch")


def canonical_execution_commit_decision_binding_digest(
    binding: ExecutionCommitDecisionBindingV2,
) -> str:
    """RFC-8785 execution-commit-decision-binding/1.0, excluding own digest."""
    ...


@dataclass(frozen=True)
class ExecutionCommitRecordV2:
    transaction_id: str
    revision: int
    state: ExecutionCommitStateV2
    external_effect_fenced: bool
    decision_digest: str | None
    commit_decision_binding: ExecutionCommitDecisionBindingV2 | None
    updated_at: float

    def __post_init__(self) -> None:
        committed_path_states = {
            ExecutionCommitStateV2.COMMIT_DECIDED,
            ExecutionCommitStateV2.COMMITTING,
            ExecutionCommitStateV2.COMMIT_APPLIED,
            ExecutionCommitStateV2.FINALIZING_VISIBILITY,
            ExecutionCommitStateV2.COMMITTED,
        }
        if self.state in committed_path_states:
            if self.commit_decision_binding is None:
                raise ValueError("commit_state_requires_admission_binding")
            if self.decision_digest != self.commit_decision_binding.binding_digest:
                raise ValueError("commit_decision_digest_mismatch")
        elif self.state is ExecutionCommitStateV2.IN_DOUBT:
            if (self.commit_decision_binding is None) != (self.decision_digest is None):
                raise ValueError("in_doubt_decision_fields_all_or_none")
        elif self.commit_decision_binding is not None or self.decision_digest is not None:
            raise ValueError("precommit_or_abort_state_forbids_decision_binding")


@dataclass(frozen=True)
class ParticipantRetryPolicyV2:
    max_attempts: int
    initial_backoff_ms: int
    max_backoff_ms: int


@dataclass(frozen=True, repr=False)
class ParticipantOperationContextV2:
    operation_attempt_id: str
    absolute_deadline_monotonic: float
    retry_policy: ParticipantRetryPolicyV2
    cancellation: CancellationToken = field(repr=False, compare=False)


class ExecutionFenceOperationV2(str, Enum):
    PREPARE = "prepare"
    EFFECT_DISPATCH = "effect_dispatch"
    RECONCILE_PROBE = "reconcile_probe"
    HIDDEN_COMMIT = "hidden_commit"
    BEGIN_VISIBILITY_FINALIZE = "begin_visibility_finalize"
    VISIBILITY_FINALIZE = "visibility_finalize"
    COMMITTED_MARKER = "committed_marker"
    RESULT_BIND = "result_bind"


@dataclass(frozen=True)
class ExecutionFinalizationFenceV2:
    intent_ref: InvocationFinalizationIntentRefV2
    coordinator_recovery_ref: ExecutionCommitRecoveryRefV2
    operation: ExecutionFenceOperationV2
    fence_digest: str


def canonical_execution_finalization_fence_digest(
    fence: ExecutionFinalizationFenceV2,
) -> str:
    """Hashes every field except fence_digest under execution-fence/2.0."""
    ...


@runtime_checkable
class ExecutionFinalizationFenceAuthorityV2(Protocol):
    def issue_current(
        self,
        *,
        intent_reference: str,
        coordinator_recovery_ref: ExecutionCommitRecoveryRefV2,
        operation: ExecutionFenceOperationV2,
    ) -> ExecutionFinalizationFenceV2: ...
    def require_current(
        self,
        fence: ExecutionFinalizationFenceV2,
        *,
        transaction_id: str,
        operation: ExecutionFenceOperationV2,
    ) -> FenceValidationReceiptV2: ...


@dataclass(frozen=True)
class FenceValidationReceiptV2:
    intent_ref: InvocationFinalizationIntentRefV2
    coordinator_recovery_ref: ExecutionCommitRecoveryRefV2
    transaction_id: str
    operation: ExecutionFenceOperationV2
    coordinator_state: ExecutionCommitStateV2
    evidence_set_digest: str
    validation_digest: str


def canonical_fence_validation_receipt_digest(
    receipt: FenceValidationReceiptV2,
) -> str:
    """RFC-8785 execution-fence-validation/1.0, excluding its digest."""
    ...


@dataclass(frozen=True)
class CommittedExecutionMarkerV2:
    record_ref: str
    record_digest: str
    transaction_id: str
    revision: int
    state: Literal[ExecutionCommitStateV2.COMMITTED]


class ResolutionDispositionV2(str, Enum):
    RESOLVED = "resolved"
    NO_FACT = "no_fact"


class ResolvedReferenceKindV2(str, Enum):
    ARTIFACT = "artifact"
    CREDENTIAL = "credential"
    SESSION = "session"
    ROUTE = "route"
    C2_RESOURCE = "c2_resource"
    FACT = "fact"
    AUDIT = "audit"
    DECISION_TRACE = "decision_trace"


class DraftReferenceKindV2(str, Enum):
    ARTIFACT = "artifact_draft"
    SENSITIVE_BATCH = "sensitive_batch_draft"
    MANAGED_RESOURCE = "managed_resource_draft"
    OBSERVATION = "observation_draft"
    FACT = "fact_draft"
    AUDIT_OUTBOX = "audit_outbox_draft"
    DECISION_TRACE = "decision_trace_draft"
    EXTERNAL_EFFECT_OUTPUT = "external_effect_output_draft"


@dataclass(frozen=True)
class ResolvedOpaqueReferenceV2:
    final_kind: ResolvedReferenceKindV2
    final_reference: str
    final_digest: str


@dataclass(frozen=True)
class ResolvedDraftReferenceV2:
    source_draft_id: str
    source_draft_type: DraftReferenceKindV2
    final_references: tuple[ResolvedOpaqueReferenceV2, ...]
    disposition: ResolutionDispositionV2
    no_fact_receipt_ref: str | None
    no_fact_receipt_digest: str | None


@dataclass(frozen=True)
class ParticipantPayloadDraftRefV2:
    transaction_id: str
    draft_id: str
    payload_schema_id: str
    payload_digest: str


@dataclass(frozen=True)
class AuditOutboxDraftRefV2:
    transaction_id: str
    draft_id: str
    event_schema_id: str
    event_digest: str


@dataclass(frozen=True)
class DecisionTraceDraftRefV2:
    transaction_id: str
    draft_id: str
    trace_schema_id: Literal["decision-trace/2.0"]
    trace_digest: str


class ApprovalGraphEventV2(str, Enum):
    ROOT_OPENED = "root_opened"
    ROUTER_EDGE_AUTHORIZED = "router_edge_authorized"
    ATTEMPT_RESERVED = "attempt_reserved"
    ATTEMPT_STARTED = "attempt_started"
    ATTEMPT_RELEASED = "attempt_released"
    ATTEMPT_NOT_CREATED = "attempt_not_created"


class DecisionTraceOutcomePhaseV2(str, Enum):
    PRE_PROVIDER = "pre_provider"
    PROVIDER_RESULT = "provider_result"


@dataclass(frozen=True)
class DecisionTraceRecordV2:
    schema_version: Literal["2.0"]
    request_id: str
    execution_id: str
    action_id: str
    transaction_id: str
    ingress_session_ref: str
    ingress_session_revision: int
    principal_ref: str
    principal_revision: int
    mission_ref: str
    mission_revision: int
    approval_ref: str | None
    approval_revision: int | None
    attempt_group_id: str
    approval_graph_event: ApprovalGraphEventV2
    attempt_lease_state: AttemptLeaseState | None
    outcome_phase: DecisionTraceOutcomePhaseV2
    root_action_id: str
    parent_action_id: str | None
    execution_graph_id: str
    killchain_stage: str | None
    operation_id: str | None
    target_decision_digest: str
    budget_digest: str
    reference_revision_digests: tuple[str, ...]
    fact_revision_digests: tuple[str, ...]
    policy_decision_digest: str
    provider_result_digest: str | None

    def __post_init__(self) -> None:
        if (self.approval_ref is None) != (self.approval_revision is None):
            raise ValueError("approval_trace_fields_all_or_none")
        if not self.request_id or not self.execution_id or not self.root_action_id:
            raise ValueError("decision_trace_identity_missing")
        if (self.outcome_phase is DecisionTraceOutcomePhaseV2.PROVIDER_RESULT) != (
            self.provider_result_digest is not None
        ):
            raise ValueError("provider_result_trace_phase_mismatch")
        match self.approval_graph_event:
            case (
                ApprovalGraphEventV2.ROOT_OPENED
                | ApprovalGraphEventV2.ROUTER_EDGE_AUTHORIZED
                | ApprovalGraphEventV2.ATTEMPT_NOT_CREATED
            ):
                if self.attempt_lease_state is not None:
                    raise ValueError("attempt_state_must_be_absent")
            case ApprovalGraphEventV2.ATTEMPT_RESERVED:
                if self.attempt_lease_state is not AttemptLeaseState.PENDING:
                    raise ValueError("reserved_attempt_state")
            case ApprovalGraphEventV2.ATTEMPT_STARTED:
                if self.attempt_lease_state is not AttemptLeaseState.STARTED:
                    raise ValueError("started_attempt_state")
            case ApprovalGraphEventV2.ATTEMPT_RELEASED:
                if self.attempt_lease_state is not AttemptLeaseState.RELEASED:
                    raise ValueError("released_attempt_state")
            case unexpected:
                assert_never(unexpected)


def canonical_decision_trace_digest(record: DecisionTraceRecordV2) -> str:
    """RFC-8785 digest tagged decision-trace/2.0 over every exact field."""
    ...


@dataclass(frozen=True)
class AuditEventV2:
    schema_version: Literal["2.0"]
    execution_id: str
    action_id: str
    transaction_id: str
    event_type: str
    reason_codes: tuple[str, ...]
    redacted_payload_digest: str


@dataclass(frozen=True)
class StagedDecisionTraceV2:
    draft_ref: DecisionTraceDraftRefV2
    registration_ref: ParticipantRegistrationRefV2


@dataclass(frozen=True)
class StagedAuditOutboxV2:
    draft_ref: AuditOutboxDraftRefV2
    registration_ref: ParticipantRegistrationRefV2


@runtime_checkable
class DecisionTraceStagerV2(Protocol):
    def stage(
        self,
        record: DecisionTraceRecordV2,
    ) -> StagedDecisionTraceV2: ...


@runtime_checkable
class AuditOutboxStagerV2(Protocol):
    def stage(self, event: AuditEventV2) -> StagedAuditOutboxV2: ...


@dataclass(frozen=True)
class SecretDraftRefV2:
    transaction_id: str
    draft_id: str
    secret_schema_id: str
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2


@dataclass(frozen=True)
class CredentialDraftRefV2:
    transaction_id: str
    draft_id: str
    credential_schema_id: str
    metadata_digest: str


@dataclass(frozen=True)
class FactDraftRefV2:
    transaction_id: str
    draft_id: str
    fact_type_id: str
    payload_digest: str


@dataclass(frozen=True)
class StagedSensitiveBatchV2:
    batch_draft_ref: SensitiveBatchDraftRefV2
    secret_draft_refs: tuple[SecretDraftRefV2, ...]
    credential_draft_refs: tuple[CredentialDraftRefV2, ...]
    fact_draft_refs: tuple[FactDraftRefV2, ...]
    secret_registration_refs: tuple[ParticipantRegistrationRefV2, ...]
    credential_registration_refs: tuple[ParticipantRegistrationRefV2, ...]
    fact_registration_refs: tuple[ParticipantRegistrationRefV2, ...]
    aggregator_registration_ref: ParticipantRegistrationRefV2
```

Callers select only the closed fence operation, never an intent phase/rank.
The concrete `ExecutionFinalizationFenceAuthorityV2` reads intent and
coordinator state/revision and derives
the exact state/evidence rule:

```text
PREPARE             -> OPEN|PREPARING + matching coordinator revision
EFFECT_DISPATCH     -> PREPARED + effect-ready authorization whose reversible
                       receipt-set digest matches the coordinator store
HIDDEN_COMMIT       -> COMMIT_DECIDED|COMMITTING
BEGIN_VISIBILITY_FINALIZE -> COMMIT_APPLIED + complete hidden-commit receipt set;
                             CASes state to FINALIZING_VISIBILITY
VISIBILITY_FINALIZE -> FINALIZING_VISIBILITY + complete hidden-commit receipt set
COMMITTED_MARKER    -> FINALIZING_VISIBILITY + complete finalize receipt set
RESULT_BIND         -> a store-read COMMITTED marker with matching digest
RECONCILE_PROBE     -> IN_DOUBT or an explicit persisted roll-forward state;
                       query/probe only
```

The exact operation, coordinator state/revision and evidence-set digest are all
covered by the issued fence digest. EFFECT_DISPATCH's pre-dispatch authorization
is written after every reversible prepare and before any backend I/O (the effect
journal separately records DISPATCHING and its confirmed/unknown result).
Another operation, an earlier/stale intent revision, mismatched coordinator/
transaction or caller-constructed fence fails before lifecycle I/O. Coordinator
and result-store APIs request and revalidate operation-specific fences
internally; callers never choose a minimum phase.
The authority accepts only the stable intent reference, resolves and read-backs
its latest monotonic revision internally, then puts that exact current ref in
the fence; a caller cannot pin or supply a stale revision. Before first
visibility call the coordinator obtains BEGIN_VISIBILITY_FINALIZE and durably
CASes COMMIT_APPLIED→FINALIZING_VISIBILITY. Each initial/retry participant
finalize call obtains a fresh VISIBILITY_FINALIZE fence in that state, so a
crash records in-progress visibility without making retry authorization fail.

The pre-dispatch checkpoint is exact
`EffectDispatchAuthorizationV2(transaction_id, external_effect_registration_identity,
reversible_prepare_set_digest, no_return_admission_ref,
no_return_admission_digest, coordinator_revision, authorization_digest)`.
It is non-null iff the intent is at least EFFECT_FENCED and is immutable after
attachment. `dispatch_terminal_effect()` first reads it back and obtains the
EFFECT_DISPATCH fence, then the participant writes its separate DISPATCHING
journal row before backend I/O. Thus an attached authorization alone never
claims that the effect occurred; startup decides from both records.
`ExternalEffectRegistrationIdentityV2` is dependency-light evidence, not a
caller-selectable participant ref: its kind is implicitly and exclusively
`EXTERNAL_EFFECT`. The coordinator derives it from the store-issued
registration and validates transaction, participant ID and registration digest
against that record before authorizing dispatch. This keeps
`execution_recovery_types.py` independent of commit-owned registration DTOs.

`SecretDraftRefV2.sealed_record_digest` covers only ciphertext/envelope metadata;
its keyed `integrity_tag` authenticates plaintext without becoming a dictionary
oracle. `CredentialDraftRefV2.metadata_digest` covers only non-sensitive fields
and opaque `secret://` references. No `payload_digest`/`content_digest` in these
refs may hash secret plaintext.

The participant payload is a closed union. It contains only staged refs,
bounded requests and digests; it never contains a participant object, store,
secret material or live handle:

```python
class LocalStoreParticipantIdV2(str, Enum):
    SECRET = "secret"
    CREDENTIAL = "credential"
    SENSITIVE_OBSERVATION = "sensitive_observation"
    FACT = "fact"
    OBSERVATION = "observation"
    ARTIFACT = "artifact"
    DECISION_TRACE = "decision_trace"
    PARTICIPANT_PAYLOAD = "participant_payload"


class ExternalEffectKindV2(str, Enum):
    DEPLOYMENT_START = "deployment_start"
    RESOURCE_CLEANUP = "resource_cleanup"
    REMOTE_OPERATION = "remote_operation"


@dataclass(frozen=True)
class DeferredManagedResourceRequestV2:
    """Logical resource whose live identity is attached during prepare."""

    resource_kind: ManagedResourceKind
    target: str | None
    lifecycle_owner: str
    close_action_id: str | None
    expires_at: float | None
    preallocated_reference: str | None = None


@dataclass(frozen=True)
class SecretStoreParticipantPayloadV2:
    store_id: Literal[LocalStoreParticipantIdV2.SECRET]
    draft_refs: tuple[SecretDraftRefV2, ...]


@dataclass(frozen=True)
class CredentialStoreParticipantPayloadV2:
    store_id: Literal[LocalStoreParticipantIdV2.CREDENTIAL]
    draft_refs: tuple[CredentialDraftRefV2, ...]


@dataclass(frozen=True)
class SensitiveObservationStoreParticipantPayloadV2:
    store_id: Literal[LocalStoreParticipantIdV2.SENSITIVE_OBSERVATION]
    batch_draft_ref: SensitiveBatchDraftRefV2
    secret_registration_refs: tuple[ParticipantRegistrationRefV2, ...]
    credential_registration_refs: tuple[ParticipantRegistrationRefV2, ...]
    fact_registration_refs: tuple[ParticipantRegistrationRefV2, ...]


@dataclass(frozen=True)
class FactStoreParticipantPayloadV2:
    store_id: Literal[LocalStoreParticipantIdV2.FACT]
    draft_refs: tuple[FactDraftRefV2, ...]


@dataclass(frozen=True)
class ObservationStoreParticipantPayloadV2:
    store_id: Literal[LocalStoreParticipantIdV2.OBSERVATION]
    draft_refs: tuple[ObservationDraftRefV2, ...]


@dataclass(frozen=True)
class ArtifactStoreParticipantPayloadV2:
    store_id: Literal[LocalStoreParticipantIdV2.ARTIFACT]
    draft_refs: tuple[ArtifactDraftRefV2, ...]


@dataclass(frozen=True)
class DecisionTraceStoreParticipantPayloadV2:
    store_id: Literal[LocalStoreParticipantIdV2.DECISION_TRACE]
    draft_ref: DecisionTraceDraftRefV2


@dataclass(frozen=True)
class ParticipantPayloadStoreParticipantPayloadV2:
    store_id: Literal[LocalStoreParticipantIdV2.PARTICIPANT_PAYLOAD]
    draft_refs: tuple[ParticipantPayloadDraftRefV2, ...]


LocalStoreParticipantRegistrationPayloadV2: TypeAlias = (
    SecretStoreParticipantPayloadV2
    | CredentialStoreParticipantPayloadV2
    | SensitiveObservationStoreParticipantPayloadV2
    | FactStoreParticipantPayloadV2
    | ObservationStoreParticipantPayloadV2
    | ArtifactStoreParticipantPayloadV2
    | DecisionTraceStoreParticipantPayloadV2
    | ParticipantPayloadStoreParticipantPayloadV2
)


@dataclass(frozen=True)
class ManagedResourceParticipantRegistrationPayloadV2:
    resource_request: ManagedResourceStageRequestV2


@dataclass(frozen=True)
class CrossProcessResourceParticipantRegistrationPayloadV2:
    resource_request: DeferredManagedResourceRequestV2
    control_payload_ref: ParticipantPayloadDraftRefV2
    visibility_mode: Literal[ParticipantVisibilityModeV2.EXPLICIT_FINALIZE]


@dataclass(frozen=True)
class CrossProcessControlParticipantRegistrationPayloadV2:
    control_payload_ref: ParticipantPayloadDraftRefV2
    visibility_mode: Literal[ParticipantVisibilityModeV2.EXPLICIT_FINALIZE]


@dataclass(frozen=True)
class ExternalEffectParticipantRegistrationPayloadV2:
    effect_kind: ExternalEffectKindV2
    effect_plan_ref: ParticipantPayloadDraftRefV2
    resource_request: DeferredManagedResourceRequestV2 | None


@dataclass(frozen=True)
class ExecutionResultParticipantRegistrationPayloadV2:
    result_draft_ref: ExecutionResultDraftRefV2


@dataclass(frozen=True)
class AuditOutboxParticipantRegistrationPayloadV2:
    outbox_draft_ref: AuditOutboxDraftRefV2


ProviderParticipantRegistrationPayloadV2: TypeAlias = (
    CrossProcessResourceParticipantRegistrationPayloadV2
    | CrossProcessControlParticipantRegistrationPayloadV2
    | ExternalEffectParticipantRegistrationPayloadV2
)


InternalParticipantRegistrationPayloadV2: TypeAlias = (
    LocalStoreParticipantRegistrationPayloadV2
    | ManagedResourceParticipantRegistrationPayloadV2
    | ProviderParticipantRegistrationPayloadV2
    | ExecutionResultParticipantRegistrationPayloadV2
    | AuditOutboxParticipantRegistrationPayloadV2
)
```

`ParticipantDraftRefV2` is the single closed draft-ref union owned by PR-5:

```python
ParticipantDraftRefV2: TypeAlias = (
    ObservationDraftRefV2
    | ArtifactDraftRefV2
    | ManagedResourceDraftRefV2
    | SensitiveBatchDraftRefV2
    | SecretDraftRefV2
    | CredentialDraftRefV2
    | FactDraftRefV2
    | ExecutionResultDraftRefV2
    | AuditOutboxDraftRefV2
    | DecisionTraceDraftRefV2
    | ParticipantPayloadDraftRefV2
)
```

`DecisionTraceStagerV2` and `AuditOutboxStagerV2` are executor-internal PR-5
services; neither appears in provider context. They canonical-encode the closed
record/event, recompute digest, bind current execution/action/transaction, stage
the draft and atomically register the matching DECISION_TRACE/AUDIT_OUTBOX
participant. Their returned registration refs are mandatory inputs to the
executor-derived normalized-result dependency set. Unknown event type, raw
payload, identity mismatch or digest mismatch fails before result staging.

Registration has one exact return contract: a closed result union. `register()`
never alternates between unrelated bare return types.

```python
@dataclass(frozen=True)
class ParticipantRegistrationRefV2:
    transaction_id: str
    participant_id: str
    participant_kind: ParticipantKindV2
    registration_digest: str


@dataclass(frozen=True)
class RegistrationOnlyResultV2:
    registration_ref: ParticipantRegistrationRefV2
    result_kind: Literal["registration_only"] = field(
        default="registration_only",
        init=False,
    )


@dataclass(frozen=True)
class ManagedResourceRegistrationResultV2:
    registration_ref: ParticipantRegistrationRefV2
    resource_draft_ref: ManagedResourceDraftRefV2
    result_kind: Literal["managed_resource"] = field(
        default="managed_resource",
        init=False,
    )


@dataclass(frozen=True)
class CrossProcessResourceRegistrationResultV2:
    registration_ref: ParticipantRegistrationRefV2
    resource_draft_ref: ManagedResourceDraftRefV2
    control_payload_ref: ParticipantPayloadDraftRefV2
    result_kind: Literal["cross_process_resource"] = field(
        default="cross_process_resource",
        init=False,
    )


@dataclass(frozen=True)
class CrossProcessControlRegistrationResultV2:
    registration_ref: ParticipantRegistrationRefV2
    control_payload_ref: ParticipantPayloadDraftRefV2
    result_kind: Literal["cross_process_control"] = field(
        default="cross_process_control",
        init=False,
    )


@dataclass(frozen=True)
class ExternalEffectRegistrationResultV2:
    registration_ref: ParticipantRegistrationRefV2
    resource_draft_ref: ManagedResourceDraftRefV2 | None
    effect_plan_ref: ParticipantPayloadDraftRefV2
    result_kind: Literal["external_effect"] = field(
        default="external_effect",
        init=False,
    )


ParticipantRegistrationResultV2: TypeAlias = (
    RegistrationOnlyResultV2
    | ManagedResourceRegistrationResultV2
    | CrossProcessResourceRegistrationResultV2
    | CrossProcessControlRegistrationResultV2
    | ExternalEffectRegistrationResultV2
)

ProviderParticipantRegistrationResultV2: TypeAlias = (
    CrossProcessResourceRegistrationResultV2
    | CrossProcessControlRegistrationResultV2
    | ExternalEffectRegistrationResultV2
)
```

Exact payload/result invariants:

```text
LocalStore/ExecutionResult/AuditOutbox payload
    → RegistrationOnlyResultV2

ParticipantPayloadDraftRefV2
    → ParticipantPayloadStoreParticipantPayloadV2(
        store_id=PARTICIPANT_PAYLOAD,
        draft_refs=(payload_ref,))
    → RegistrationOnlyResultV2; this registration is created atomically by
      stage_participant_payload(), never through the provider facade

ManagedResource payload
    → ManagedResourceRegistrationResultV2

CrossProcessResource payload
    → CrossProcessResourceRegistrationResultV2

CrossProcessControl payload
    → CrossProcessControlRegistrationResultV2

ExternalEffect payload
    → ExternalEffectRegistrationResultV2
    → `resource_request is None` iff `resource_draft_ref is None`; otherwise the
      coordinator atomically preallocates a transaction-private resource draft
      matching request kind/target/lifecycle and returns it in the result

all registration/draft/payload refs use the current transaction_id
each exact local-store payload accepts only its named draft-ref type
unknown payload/result pairing fails closed
```

Registration spec and provider facade:

```python
class ParticipantRegistrationContractViolation(RuntimeError):
    pass


@dataclass(frozen=True)
class ProviderParticipantRegistrationSpecV2:
    participant_kind: ParticipantKindV2
    registration_schema_id: str
    idempotency_suffix: str
    prepare_depends_on: tuple[ParticipantRegistrationRefV2, ...]
    commit_depends_on: tuple[ParticipantRegistrationRefV2, ...]
    payload: ProviderParticipantRegistrationPayloadV2


@dataclass(frozen=True)
class InternalParticipantRegistrationSpecV2:
    participant_kind: ParticipantKindV2
    registration_schema_id: str
    idempotency_key: str
    payload_digest: str
    prepare_depends_on: tuple[ParticipantRegistrationRefV2, ...]
    commit_depends_on: tuple[ParticipantRegistrationRefV2, ...]
    payload: InternalParticipantRegistrationPayloadV2


@runtime_checkable
class ProviderParticipantRegistrationFacade(Protocol):
    @property
    def transaction_id(self) -> str: ...

    def register(
        self,
        spec: ProviderParticipantRegistrationSpecV2,
    ) -> ProviderParticipantRegistrationResultV2: ...
```

Provider code cannot register local secret/credential/fact, managed-resource,
execution-result or audit participants. Staging methods register their matching
internal participant atomically. For provider registration the coordinator
canonical-encodes the closed payload, computes `payload_digest`, constructs the
full idempotency key from transaction/request/action/mission/subject plus that
digest, validates the `ParticipantKindV2`↔payload↔result table, and returns a
store-owned result. A provider-supplied digest or full idempotency key is never
trusted. `ParticipantRegistrationContractViolation` is defined once in
`core/actions/provider_participants.py` and is the fail-closed mismatch error.
For ordinary reversible participants the two dependency tuples are identical.
`prepare_depends_on` is the graph used before irreversible dispatch;
`commit_depends_on` is the hidden-commit/final-reference graph. Both contain
deduplicated refs from the current transaction, and the prepare set must be a
subset of the commit set. Only an execution-result participant may add the
terminal external-effect registration to `commit_depends_on` without adding it
to `prepare_depends_on`; this exact phased-edge exception lets the result draft
prepare before dispatch and consume the effect receipt only during hidden
commit. Every other differing pair is rejected at registration.

The concrete participant lifecycle is exact. Reversible prepare, deterministic
no-effect failure, confirmed irreversible effect and uncertainty are distinct:

```python
NonExternalParticipantKindV2: TypeAlias = Literal[
    ParticipantKindV2.LOCAL_STORE,
    ParticipantKindV2.MANAGED_RESOURCE,
    ParticipantKindV2.CROSS_PROCESS_RESOURCE,
    ParticipantKindV2.CROSS_PROCESS_CONTROL,
    ParticipantKindV2.EXECUTION_RESULT,
    ParticipantKindV2.AUDIT_OUTBOX,
]


class PrepareEffectDispositionV2(str, Enum):
    REVERSIBLE = "reversible"
    EFFECT_CONFIRMED = "effect_confirmed"


@dataclass(frozen=True)
class ReversibleParticipantPrepareReceiptV2:
    transaction_id: str
    participant_id: str
    participant_kind: NonExternalParticipantKindV2
    receipt_ref: str
    receipt_digest: str
    participant_revision: int
    state: Literal[ParticipantStateV2.PREPARED]
    effect_disposition: Literal[PrepareEffectDispositionV2.REVERSIBLE]


@dataclass(frozen=True)
class ExternalEffectConfirmedReceiptV2:
    transaction_id: str
    participant_id: str
    participant_kind: Literal[ParticipantKindV2.EXTERNAL_EFFECT]
    receipt_ref: str
    receipt_digest: str
    participant_revision: int
    state: Literal[ParticipantStateV2.PREPARED]
    effect_disposition: Literal[PrepareEffectDispositionV2.EFFECT_CONFIRMED]


ParticipantPrepareReceiptV2: TypeAlias = ReversibleParticipantPrepareReceiptV2 | ExternalEffectConfirmedReceiptV2


@dataclass(frozen=True)
class ParticipantPrepareFailedReceiptV2:
    transaction_id: str
    participant_id: str
    participant_kind: ParticipantKindV2
    failure_ref: str
    failure_digest: str
    participant_revision: int
    no_external_effect: Literal[True]
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class ParticipantInDoubtReceiptV2:
    transaction_id: str
    participant_id: str
    participant_kind: Literal[ParticipantKindV2.EXTERNAL_EFFECT]
    effect_ref: str
    probe_ref: str
    dispatch_journal_ref: str
    participant_revision: int
    state: Literal[ParticipantStateV2.IN_DOUBT]


ParticipantPrepareOutcomeV2: TypeAlias = (
    ParticipantPrepareReceiptV2 | ParticipantPrepareFailedReceiptV2 | ParticipantInDoubtReceiptV2
)

ReversiblePrepareOutcomeV2: TypeAlias = ReversibleParticipantPrepareReceiptV2 | ParticipantPrepareFailedReceiptV2

TerminalEffectPrepareOutcomeV2: TypeAlias = (
    ExternalEffectConfirmedReceiptV2 | ParticipantPrepareFailedReceiptV2 | ParticipantInDoubtReceiptV2
)


@dataclass(frozen=True)
class DependencyPrepareBindingV2:
    registration_ref: ParticipantRegistrationRefV2
    prepare_receipt_ref: str
    prepare_receipt_digest: str
    prepare_revision: int


@dataclass(frozen=True)
class ParticipantPrepareRequestV2:
    transaction_id: str
    participant_id: str
    coordinator_revision: int
    dependency_bindings: tuple[DependencyPrepareBindingV2, ...]
    operation: ParticipantOperationContextV2
    finalization_fence: ExecutionFinalizationFenceV2


@dataclass(frozen=True)
class DependencyCommitBindingV2:
    registration_ref: ParticipantRegistrationRefV2
    prepare_receipt_ref: str
    prepare_receipt_digest: str
    prepare_revision: int
    commit_receipt_ref: str
    commit_receipt_digest: str
    commit_revision: int
    resolved_references: tuple[ResolvedDraftReferenceV2, ...]


@dataclass(frozen=True)
class ParticipantCommitRequestV2:
    transaction_id: str
    participant_id: str
    own_prepare_receipt: ParticipantPrepareReceiptV2
    dependency_bindings: tuple[DependencyCommitBindingV2, ...]
    coordinator_revision: int
    decision_digest: str
    operation: ParticipantOperationContextV2
    finalization_fence: ExecutionFinalizationFenceV2


@dataclass(frozen=True)
class HiddenExecutionResultCommitRefV2:
    transaction_id: str
    hidden_ref: str
    hidden_digest: str
    execution_id: str
    result_draft_id: str


@dataclass(frozen=True)
class ParticipantCommitReceiptV2:
    transaction_id: str
    participant_id: str
    commit_receipt_ref: str
    commit_digest: str
    participant_revision: int
    resolved_references: tuple[ResolvedDraftReferenceV2, ...]
    hidden_execution_result_ref: HiddenExecutionResultCommitRefV2 | None
    state: Literal[ParticipantStateV2.COMMITTED_HIDDEN]


@dataclass(frozen=True)
class ParticipantFinalizeReceiptV2:
    transaction_id: str
    participant_id: str
    finalize_receipt_ref: str
    finalize_digest: str
    participant_revision: int
    state: Literal[ParticipantStateV2.FINALIZED]


@dataclass(frozen=True)
class ParticipantRollbackReceiptV2:
    transaction_id: str
    participant_id: str
    participant_kind: ParticipantKindV2
    participant_revision: int
    rollback_receipt_ref: str
    rollback_digest: str
    state: Literal[ParticipantStateV2.ROLLED_BACK]


@dataclass(frozen=True)
class ParticipantNeverPreparedReceiptV2:
    transaction_id: str
    participant_id: str
    participant_kind: NonExternalParticipantKindV2
    registration_revision: int
    registration_digest: str
    draft_invalidation_receipt_ref: str
    draft_invalidation_digest: str
    state: Literal[ParticipantStateV2.ABORTED_UNPREPARED]


ParticipantAbortEvidenceV2: TypeAlias = ParticipantRollbackReceiptV2 | ParticipantNeverPreparedReceiptV2


class ReconcileDispositionV2(str, Enum):
    STILL_IN_DOUBT = "still_in_doubt"
    RESOLVED_COMMIT = "resolved_commit"
    RESOLVED_ABORT = "resolved_abort"
    ROLL_FORWARD = "roll_forward"
    FAILED = "failed"


@dataclass(frozen=True)
class ParticipantReconcileResultV2:
    transaction_id: str
    participant_id: str
    state: ParticipantStateV2
    disposition: ReconcileDispositionV2
    participant_revision: int
    receipt_ref: str | None
    reason_codes: tuple[str, ...]


@runtime_checkable
class ExecutionCommitParticipant(Protocol):
    @property
    def participant_id(self) -> str: ...
    @property
    def transaction_id(self) -> str: ...
    @property
    def participant_kind(self) -> ParticipantKindV2: ...

    def prepare(
        self,
        request: ParticipantPrepareRequestV2,
    ) -> ParticipantPrepareOutcomeV2: ...

    def commit(
        self,
        request: ParticipantCommitRequestV2,
    ) -> ParticipantCommitReceiptV2: ...

    def finalize_visibility(
        self,
        prepare_receipt: ParticipantPrepareReceiptV2,
        commit_receipt: ParticipantCommitReceiptV2,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantFinalizeReceiptV2: ...

    def rollback(
        self,
        receipt: ParticipantPrepareReceiptV2 | None,
        operation: ParticipantOperationContextV2,
    ) -> ParticipantRollbackReceiptV2: ...

    def reconcile(
        self,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantReconcileResultV2: ...
```

Only `ExecutionCommitCoordinator` can construct concrete participants through
`ExecutionCommitParticipantRegistry` and invoke their lifecycle:

```python
@runtime_checkable
class ParticipantPayloadReadLeaseV2(Protocol):
    @property
    def reference(self) -> ParticipantPayloadDraftRefV2: ...
    @property
    def prepared_revision(self) -> int: ...
    @property
    def read_view_digest(self) -> str: ...
    def borrow_canonical_payload(self) -> ContextManager[memoryview]: ...
    def close(self) -> None: ...


@dataclass(frozen=True, repr=False)
class ParticipantPayloadReadViewV2:
    reference: ParticipantPayloadDraftRefV2
    prepared_revision: int
    read_view_digest: str
    lease: ParticipantPayloadReadLeaseV2 = field(repr=False, compare=False)


@runtime_checkable
class ParticipantPayloadResolverV2(Protocol):
    def require(
        self,
        reference: ParticipantPayloadDraftRefV2,
        *,
        expected_transaction_id: str,
        expected_schema_id: str,
        expected_payload_digest: str,
        operation: ParticipantOperationContextV2,
    ) -> ParticipantPayloadReadViewV2: ...


@dataclass(frozen=True)
class ParticipantExecutionAuthorityBindingV2:
    execution_id: str
    action_id: str
    transaction_id: str
    mission_id: str
    subject_id: str
    checkout_recovery_ref: CheckoutRecoveryRefV2
    intent_reference: str
    issued_intent_revision: int
    issued_intent_digest: str
    coordinator_transaction_id: str
    coordinator_record_ref: str
    issued_coordinator_revision: int
    issued_coordinator_digest: str
    binding_digest: str


def canonical_participant_execution_authority_digest(
    binding: ParticipantExecutionAuthorityBindingV2,
) -> str:
    """RFC-8785 participant-execution-authority/1.0, excluding own digest."""
    ...


@runtime_checkable
class ParticipantExecutionAuthorityFactoryV2(Protocol):
    def issue(
        self,
        *,
        creation: ExecutionCreationReceiptV2,
        current_intent: InvocationFinalizationIntentRecordV2,
        checkout_recovery_ref: CheckoutRecoveryRefV2,
        coordinator_recovery_ref: ExecutionCommitRecoveryRefV2,
    ) -> ParticipantExecutionAuthorityBindingV2: ...


@runtime_checkable
class ExecutionCommitParticipantRegistry(Protocol):
    @property
    def payload_resolver(self) -> ParticipantPayloadResolverV2: ...
    def materialize(
        self,
        transaction_id: str,
        spec: InternalParticipantRegistrationSpecV2,
        *,
        authority: ParticipantExecutionAuthorityBindingV2,
    ) -> tuple[ExecutionCommitParticipant, ParticipantRegistrationResultV2]: ...


@dataclass(frozen=True)
class ParticipantFinalizationBindingV2:
    participant_id: str
    participant_kind: ParticipantKindV2
    prepare_revision: int
    commit_revision: int
    finalize_revision: int
    prepare_receipt_digest: str
    commit_receipt_digest: str
    finalize_receipt_digest: str


@dataclass(frozen=True)
class ExecutionVisibilityFinalizationV2:
    transaction_id: str
    expected_coordinator_revision: int
    participant_bindings: tuple[ParticipantFinalizationBindingV2, ...]
    finalization_set_digest: str


@runtime_checkable
class ExecutionCommitStoreV2(Protocol):
    def persist_committed_marker(
        self,
        finalization: ExecutionVisibilityFinalizationV2,
        fence: ExecutionFinalizationFenceV2,
    ) -> CommittedExecutionMarkerV2: ...
    def require_current_marker(
        self,
        marker: CommittedExecutionMarkerV2,
    ) -> CommittedExecutionMarkerV2: ...


@dataclass(frozen=True)
class ExecutionCommitCompletionV2:
    transaction_id: str
    state: Literal[ExecutionCommitStateV2.COMMITTED]
    execution_result_ref: ExecutionResultRefV2
    participant_bindings: tuple[ParticipantFinalizationBindingV2, ...]
    committed_result_binding: CommittedExecutionResultBindingV2


@dataclass(frozen=True)
class ExecutionCommitCreationSpecV2:
    transaction_id: str
    execution_id: str
    action_id: str
    participant_limit: int
    creation_digest: str


class ExecutionCommitCoordinator:
    transaction_id: str
    finalization_fence_authority: ExecutionFinalizationFenceAuthorityV2
    participant_authority: ParticipantExecutionAuthorityBindingV2

    def register_spec(
        self,
        spec: InternalParticipantRegistrationSpecV2,
    ) -> ParticipantRegistrationResultV2: ...

    def prepare_reversible_all(
        self,
        operation: ParticipantOperationContextV2,
    ) -> tuple[ReversiblePrepareOutcomeV2, ...]: ...
    def dispatch_terminal_effect(
        self,
        operation: ParticipantOperationContextV2,
        admission: ExecutionNoReturnAdmissionReceiptV2,
    ) -> TerminalEffectPrepareOutcomeV2 | None: ...
    def decide_abort(self) -> ExecutionCommitRecordV2: ...
    def decide_commit(
        self,
        admission: ExecutionNoReturnAdmissionReceiptV2,
    ) -> ExecutionCommitRecordV2: ...
    def commit_all_hidden(
        self,
        operation: ParticipantOperationContextV2,
    ) -> tuple[ParticipantCommitReceiptV2, ...]: ...
    def finalize_all_visibility(
        self,
        operation: ParticipantOperationContextV2,
    ) -> ExecutionVisibilityFinalizationV2: ...
    def persist_committed_marker(
        self,
        finalization: ExecutionVisibilityFinalizationV2,
    ) -> CommittedExecutionMarkerV2: ...
    def bind_committed_result(
        self,
        marker: CommittedExecutionMarkerV2,
    ) -> ExecutionCommitCompletionV2: ...
    def rollback_all(
        self,
        operation: ParticipantOperationContextV2,
    ) -> ExecutionCommitRecordV2: ...
    def reconcile_all(
        self,
        operation: ParticipantOperationContextV2,
    ) -> ExecutionCommitRecordV2: ...


@runtime_checkable
class ExecutionCommitCoordinatorFactoryV2(Protocol):
    def reserve_inert(
        self,
        *,
        creation_spec: ExecutionCommitCreationSpecV2,
        intent: InvocationFinalizationIntentRecordV2,
    ) -> ExecutionCommitRecoveryRefV2: ...
    def activate_after_intent_checkpoint(
        self,
        *,
        creation_spec: ExecutionCommitCreationSpecV2,
        intent: InvocationFinalizationIntentRecordV2,
        coordinator_recovery_ref: ExecutionCommitRecoveryRefV2,
        participant_authority: ParticipantExecutionAuthorityBindingV2,
    ) -> ExecutionCommitCoordinator: ...
    def reclaim_inert(
        self,
        coordinator_recovery_ref: ExecutionCommitRecoveryRefV2,
    ) -> CleanupHandlerReceiptV2: ...
```

The registry injects this exact internal resolver into every materialized
plan-driven participant; no participant obtains a global payload store. The
resolver re-reads only a transaction-private PREPARED payload, canonicalizes it,
and requires transaction/schema/digest/revision equality before returning a
bounded read lease. Wrong transaction, schema, digest, stale revision, consumed
view or replay under a different operation attempt fails closed. The participant
borrows the canonical payload only through the lease context and closes it in
its lifecycle-call `finally`; recovery resolves the same durable ref, so
C2 enrollment/deployment/cleanup and remote-operation plans need no ambient
service locator.
At materialization the coordinator also supplies the executor/store-issued
`ParticipantExecutionAuthorityBindingV2`, derived only from the creation record,
current intent and attached checkout/coordinator recovery refs. It is not part
of any provider payload or effect plan. The registry recomputes its digest and
binds it to the registration/participant; each participant keeps it private and
revalidates execution/action/transaction/mission/subject/checkout/intent/
coordinator identity against the operation fence before acquiring participant-
only material. Remote-operation and deployment resolvers receive its checkout,
mission and subject fields; wrong identity or stale recovery readback fails
before material/backend I/O and no global lookup fills a missing value.
`ParticipantExecutionAuthorityFactoryV2.issue()` is the sole producer. Executor
calls it after the coordinator ref is attached and supplies the read-back
binding to `activate_after_intent_checkpoint()`; the coordinator retains it and
passes it to every registry `materialize()` invoked by `register_spec()`.
Recovery deterministically reissues/verifies the same binding from the durable
creation+intent records. Intent/coordinator revisions legitimately advance, so
the binding stores stable reference/transaction identity plus the exact issued
revision/digest. Each fresh operation fence must prove the current store-read
intent and coordinator are monotonic descendants of those issued records; it
never requires frozen revision equality or accepts a changed stable reference.

Coordinator creation uses the same mandatory reserve→intent-CAS→activate
protocol as checkout and scope creation. `reserve_inert()` creates no
participant/effect and returns the store-issued recovery ref; the full desired
intent checkpoint must include that ref before `activate_after_intent_checkpoint`
can construct the live coordinator. The factory obtains the finalization fence
store as a private dependency but does not preissue a fence. The coordinator
obtains/revalidates a fresh fence at each operation. A caller-constructed or
stale fence, mismatched intent revision,
transaction, coordinator ref or phase is rejected. The recovery service reopens
the inert/active record; it is not the component that first freezes an already
live coordinator.

Prepare ordering and uncertainty:

```text
prepare_reversible_all() follows `prepare_depends_on` topologically and supplies each
participant exactly the durable prepare receipts for that set;
all reversible/local participants prepare under a fresh PREPARE fence before an
EXTERNAL_EFFECT; after their receipts are durable the coordinator checkpoints
effect-ready, issues a fresh EFFECT_DISPATCH fence and calls
dispatch_terminal_effect() exactly once;
v6 permits at most one EXTERNAL_EFFECT; it is a terminal frontier in the
prepare graph, has no prepare dependents, and no prepare runs after dispatch;
ParticipantPrepareFailedReceiptV2 → durable ABORT_DECIDED;
ParticipantInDoubtReceiptV2 → durable IN_DOUBT and probe-only reconciliation;
EFFECT_CONFIRMED → persist the effect receipt and COMMIT_DECIDED without an
abortable gap;
only reversible PREPARED receipts and a confirmed terminal effect may enter
hidden commit/finalize.
`commit_all_hidden()` follows `commit_depends_on` topologically. The
coordinator, not a
participant/provider, builds each `ParticipantCommitRequestV2` from durable
prepare/commit receipts of exactly the registration's declared
`commit_depends_on`
set. Missing, extra, stale or duplicate dependency bindings fail before the
participant commit. Store participants put their exact draft→final-reference
bindings in their commit receipts; the coordinator validates and forwards them,
never invents a final reference. The execution-result participant requires the
complete dependency set and calls `ExecutionResultStore.commit_hidden()`.
`finalize_all_visibility()` uses that same `commit_depends_on` graph in forward
topological order; it introduces no third implicit edge set. Rollback alone uses
strict reverse prepare order.
Only its receipt carries non-null `hidden_execution_result_ref`; every other
participant must carry `None`. The coordinator persists that ref and recovery
reloads/revalidates the hidden result before post-marker binding.
Before writing `COMMITTED`, the coordinator compares the exact registered
participant-id/kind set with `participant_bindings`; missing, duplicate or
unexpected bindings, or any prepare/commit/finalize digest/revision mismatch,
fail closed and remain in roll-forward reconciliation.
Global `ROLLED_BACK` is written only after the coordinator has one matching
`ParticipantAbortEvidenceV2` for every registered reversible participant.
`rollback_all()` visits only successfully PREPARED reversible participants in
strict reverse prepare-topological order (dependents before dependencies),
never calls rollback for an unprepared participant, and persists every receipt
before continuing. For each registered but never-prepared participant, its
store atomically invalidates every draft and issues
`ParticipantNeverPreparedReceiptV2`; there is no fake rollback call. An
EXTERNAL_EFFECT is excluded only with durable no-dispatch/FAILED_NO_EFFECT
evidence; possible dispatch enters IN_DOUBT instead. A failed suffix remains durable
`ROLLING_BACK`, publishes only progress and is retried idempotently; no terminal
state is inferred from a `None` return.
`finalize_all_visibility()` returns bindings but cannot claim global commit.
There is no long-lived or caller-supplied fence on the coordinator: each public
transition internally obtains and revalidates a fresh operation-specific fence
from the current intent revision, then passes it only to the participant/store
call it authorizes. `persist_committed_marker()` obtains COMMITTED_MARKER,
validates the exact registered
set and asks the sole `ExecutionCommitStoreV2` to CAS/read back a store-issued
`CommittedExecutionMarkerV2`. Only after that marker exists does
`bind_committed_result()` obtain a new RESULT_BIND fence, revalidate the
marker and invoke the result store's post-marker binding before returning
`ExecutionCommitCompletionV2`. `reconcile_all()` selects the next state itself
and obtains the exact corresponding fence; callers cannot pass a generic one.
A caller-
constructed record/dataclass is never sufficient evidence of COMMITTED.

The two prepare methods exhaustively match their distinct closed aliases with
`assert_never`: reversible preparation can never return an effect-confirmed or
in-doubt receipt, and terminal dispatch can never return a reversible receipt.
```

Single-owner invariant:

```text
ExecutionCommitCoordinator.prepare_reversible_all() and
ExecutionCommitCoordinator.dispatch_terminal_effect()
    is the only production caller of participant.prepare().

ExecutionCommitCoordinator.commit_all_hidden()
    is the only production caller of participant.commit().

ExecutionCommitCoordinator.finalize_all_visibility()
    is the only production caller of participant.finalize_visibility().

ExecutionCommitCoordinator.rollback_all()/reconcile_all()
    are the only production callers of rollback/reconcile.
```

Providers never receive participant objects and cannot invoke lifecycle methods
by type. Cross-store ACID is not claimed. Every staged record carries
`execution_transaction_id`; provisional refs never escape the transaction or
report path.

Every lifecycle call receives a fresh executor-owned bounded
`ParticipantOperationContextV2`; live runs use the root cancellation state and
startup reconciliation uses a separately authority-minted recovery token and
deadline. Attempt IDs are durable/idempotent and every daemon/backend call must
honor the deadline/retry bound. Terminal-effect dispatch, global committed
completion and post-marker result binding additionally re-read and verify the
store-issued `ExecutionFinalizationFenceV2`; stale intent revision, mismatched
coordinator ref or illegal phase fails before dispatch/visibility. The
coordinator is constructed with that intent binding, so providers cannot forge
the fence and recovery cannot block indefinitely.

### 8.3. Sensitive ingestion — one-shot zeroizable staging capability

Direct production ingestion remains forbidden:

```python
sensitive_ingestor.ingest(normalized)
```

Providers return one-shot sensitive handles. They do not receive stores or the
commit coordinator. The only publication path is:

```text
SensitiveObservationHandleV2
OwnedSensitiveObservationHandleV2
SensitiveObservationHandleFactoryV2
SensitiveBatchStagingCapabilityV2
→ executor-only atomic stage_into(SensitiveBatchStagingCapabilityV2,
  expected identity/count/size/keyed-integrity-tag)
→ StagedSensitiveBatchV2
→ executor-owned Secret, Credential and Fact store participants
→ SensitiveObservation aggregator participant depending on that exact set
→ coordinator prepare/commit or rollback
```

The sensitive buffer must be mutable and zeroizable. Immutable `bytes`, `str`,
`memoryview` over immutable bytes, or a DTO containing plaintext are forbidden.
`SensitiveIntegrityTagV2` is the dependency-free PR-4 DTO owned by
`core/actions/sensitive_integrity.py`. PR-5 imports it and solely owns the
authenticator/keyring, zeroizable-buffer, handle and staging foundation; PR-7
only imports those types when adding concrete provider-result variants.

Staging is one executor/store transaction: it parses the closed schema, creates
provisional secret/credential/fact draft refs, atomically registers their exact
store participants, then registers the SensitiveObservation aggregator with
both dependency sets equal to the unique returned registration set.
Credential/fact
participants depend on the exact secret registrations they reference. The
aggregator alone emits the batch→CREDENTIAL resolved mapping; direct
`FactDraftRefV2` participants are the sole FACT mapping, so no final fact ref is
duplicated. Sealed secret refs never enter `ExecutionResultV2`.
`StagedSensitiveBatchV2` returns all
draft/registration evidence, and the result participant depends on the
aggregator plus the direct Fact registrations. Missing/extra/cyclic edges,
unregistered draft refs or a keyed-tag/count/size mismatch roll back the entire
stage. Staging creates provisional refs, registers rollback and
reconcile metadata, and exposes no ref until global `COMMITTED`. Rollback must
delete or invalidate all staged records. If an encrypted blob cannot be
physically removed, rollback destroys the wrapping key and marks the record
`REVOKED_ABORTED`.

## 8.4. Durable commit decision, hidden commit and explicit visibility finalization

Coordinator state is the exact `ExecutionCommitStateV2` enum and durable
`ExecutionCommitRecordV2` from §8.2; no second string/state owner exists.

Semantics:

```text
OPEN/PREPARING/PREPARED:
    no known or possibly dispatched irreversible external effect → may choose
    ABORT_DECIDED;

IN_DOUBT:
    external effect may exist → rollback/retry/revoke forbidden until probe;

COMMIT_DECIDED:
    durable no-return point; only roll-forward is legal;

COMMIT_APPLIED:
    every participant commit is durable but cross-process resources remain
    COMMITTED_HIDDEN and local staged records remain unavailable to normal reads;

FINALIZING_VISIBILITY:
    coordinator invokes participant.finalize_visibility() and waits for exact
    finalize receipts;

COMMITTED:
    all required finalize receipts are durable; local normal reads may expose
    committed refs and the execution-result participant may publish its ref.
```

External-effect resolution:

```text
probe STARTED
    → IN_DOUBT → COMMIT_DECIDED

probe NOT_STARTED or FAILED_NO_EFFECT
    → IN_DOUBT → ABORT_DECIDED

probe UNKNOWN
    → remain IN_DOUBT; do not retry start
```

Before the terminal external-effect participant dispatches anything, it
durably writes `START_DISPATCHING(transaction_id, participant_id, attempt_id)`.
The backend receives that stable attempt ID and must implement start/probe
idempotency. A known `STARTED` receipt is durably recorded before return and
forces `COMMIT_DECIDED`; an uncertain return records a dispatch-journal receipt
and forces `IN_DOUBT`. Startup/finally inspect this journal even if the last
coordinator record is still `PREPARING`: `START_DISPATCHING`/`UNKNOWN` forbid
rollback, while `STARTED` forces roll-forward. The plan does not claim an atomic
write across independent stores; ordered durable records plus idempotent probe
make the crash window reconcilable. If effect journal and coordinator share one
database transaction, an implementation may strengthen this to a single CAS.

There is no claim that independent processes become visible at the same atomic
CPU/database instant. The enforceable invariant is:

```text
- daemon participant commit produces a hidden durable resource;
- local execution success is not published before daemon visibility-finalize ACK;
- after COMMIT_DECIDED neither side may roll back;
- crash after daemon finalization but before local COMMITTED is reconciled by
  QUERY_C2_RESOURCE and idempotent local roll-forward;
- callers observe `ExecutionProgressReportV2(RECONCILIATION_PENDING)` and no
  provisional local refs until the final
  coordinator COMMITTED marker.
```

For cross-process C2 resources the exact sequence is:

```text
PREPARE_C2_RESOURCE
→ PENDING

COMMIT_C2_RESOURCE
→ COMMITTED_HIDDEN

FINALIZE_C2_RESOURCE_VISIBILITY
→ externally usable daemon state + finalize receipt

persist local coordinator COMMITTED
→ local refs/result become normally readable
```

Generic rollback after `COMMIT_DECIDED` is forbidden. Every participant commit
and finalization is idempotent. Recovery from `COMMIT_APPLIED` or
`FINALIZING_VISIBILITY` retries only hidden-commit/finalize roll-forward.

### 8.5. Managed resource ownership at stage

A provider calls only the restricted staging facade:

```python
@dataclass(frozen=True)
class StagedManagedResourceV2:
    resource_draft_ref: ManagedResourceDraftRefV2
    registration_ref: ParticipantRegistrationRefV2


staged_resource = invocation.staging.stage_managed_resource(stage_request)
```

The facade delegates to an executor-owned `ManagedResourceParticipantOwner`,
which implements only the internal `ResourceOwner.accept_transient(...)` seam.
Neither the provider nor `InvocationScope` receives the full coordinator or
transaction object.

Atomic ownership transfer:

```text
ProviderStagingFacade.stage_managed_resource(request)
→ internal participant owner accepts transient handle
→ InvocationScope releases that transient only after acceptance succeeds
→ atomically registers the internal managed-resource participant
→ invisible PENDING draft + registration refs are returned together
```

Acceptance, draft creation and participant registration execute in one
executor-owned ownership transaction. `InvocationScope` releases the transient
only after that transaction commits. If any edge fails—including after an
owner tentatively accepts but before registration becomes durable—the ownership
transaction compensates by returning the transient to the scope when possible;
otherwise it closes the transient, invalidates the draft and records the close.
Thus `scope.close()` cannot destroy a successfully staged handle and no
post-accept/pre-registration orphan can escape cleanup.

Before global commit:

```text
ExecutionCommitCoordinator.rollback_all()
→ managed-resource participant closes the PENDING handle
→ draft ref becomes permanently invalid
```

After hidden commit and required visibility finalization:

```text
lifecycle store owns the ACTIVE handle
participant/coordinator no longer closes it
InvocationScope does not close it
```

Managed resource activation is the last participant commit/finalization point
before the global visibility marker. Failure before external-effect dispatch may
choose `ABORT_DECIDED`; uncertainty after dispatch enters durable `IN_DOUBT` and
cannot roll back until the effect probe resolves it. Failure after
`COMMIT_DECIDED` never rolls back or compensates: the result is
`ExecutionProgressReportV2(RECONCILIATION_PENDING)` and the reconciler
idempotently rolls activation forward
to `COMMITTED` or `FAILED_RECONCILIATION`.

## 8.6. Fail-safe finalization

Outer finally не выполняет cleanup последовательностью, которую может прервать
первая ошибка.

В executor должны храниться:

attempt_lease
approval_graph_lease
approval_graph_owner
checkout
commit_coordinator
scope
ingress_lease
primary_result
provider_call_termination
cancellation_recovery_ref
cancellation_controller_binding

В finally каждая операция выполняется независимо и добавляет ошибку в
CleanupErrorAccumulator:

0. if provider call is `DETACHED_FENCED`, persist the termination record and
   transfer checkout/scope/coordinator ownership to the termination reconciler;
   skip abort/checkout/scope close in this invocation, persist a
   `ExecutionProgressReportV2(TERMINATION_PENDING)` (not a final report), and
   continue only with ingress/graph bookkeeping;
1. otherwise release attempt, only if state=PENDING;
2. `OPEN|PREPARING|PREPARED` with no known or possibly dispatched irreversible
   effect → persist `ABORT_DECIDED` and run/schedule rollback;
3. `ABORT_DECIDED|ROLLING_BACK` → resume/schedule rollback;
4. `IN_DOUBT` → preserve all fenced participants/resources and schedule only
   probe reconciliation; do not rollback, revoke enrollment or repeat effect;
5. `COMMIT_DECIDED|COMMITTING|COMMIT_APPLIED|FINALIZING_VISIBILITY` →
   resume/schedule idempotent roll-forward;
6. terminal `ROLLED_BACK|COMMITTED|FAILED_RECONCILIATION` → no coordinator
   mutation;
7. close checkout without releasing resources fenced by an IN_DOUBT/roll-forward coordinator;
8. close InvocationScope;
9. close approval graph only when current executor is graph owner;
10. consume current root/child ingress lease.
11. independently unbind this process's
    `CancellationControllerBindingV2`; for a durable continuation/detach handoff
    do so only after custody read-back, otherwise recovery could miss a racing
    cancel;
12. only when this executor owns the graph and every child/continuation is
    terminal, CAS/read back `CancellationRecoveryStoreV2.complete_graph()`;
    child executors never complete the shared graph.

Ошибка любого шага не пропускает остальные шаги.

Creation receipts durably identify the root binding; recovery claim/budget
records durably identify each reconciler binding. Startup can therefore clear a
dead process binding with a store-issued cleanup receipt before
CLEANUP_COMPLETE; it never scans or trusts an in-memory controller registry.

Если primary_result отсутствует, создать internal_failure result.
Cleanup errors объединяются с primary outcome только после завершения всех шагов.

PR-5 `core/actions/execution_finalization.py` owns the crash-recoverable intent;
it is deliberately not part of the PR-2 result DTO foundation:

The dependency-light declarations shown first are physically owned by
`core/actions/execution_recovery_types.py`: the pure PR-5 recovery refs/states
(invocation scope, ingress, approval graph, attempt, coordinator, provider call,
cancellation and continuation),
cancellation/continuation records, the pure
`ExecutionNoReturnAdmissionBodyV2`, `ExecutionNoReturnAdmissionRefV2`,
`ExecutionNoReturnAdmissionReceiptV2` and its canonical digest, the pure
`ExternalEffectRegistrationIdentityV2`,
`ParticipantExecutionAuthorityBindingV2`, `RecoveryOwnerCleanupReceiptV2` and its
digest helpers, `ExecutionFenceOperationV2`, `ExecutionFinalizationFenceV2`,
`FenceValidationReceiptV2` and the pure
`ExecutionFinalizationFenceAuthorityV2` protocol. The light module imports no
checkout/scope/finalization/coordinator implementation. Behavioral ownership is
separate and one-way: `execution_creation_store.py` owns atomic creation;
`cleanup_operation_context.py` owns the final concrete cleanup authority,
policy/context/subject DTOs and private per-attempt recovery controllers;
`cancellation_recovery.py` owns the concrete durable cancellation store and its
creation component is callable only inside that store transaction;
`execution_cancellation_service.py` owns authenticated public cancel;
`execution_no_return_admission.py` owns the concrete admission store while its
Protocol and pure records remain in the light module;
`intent_bound_owner_factories.py` owns the generic intent-bound owner factory,
the checkout/scope/approval-graph/attempt creation specs, their four specialized
Protocols and concrete reserve→intent-CAS→activate orchestration; it imports
private factory-token hooks from those owner modules, which never import it;
`participant_authority.py` owns the sole factory that joins creation/intent/
checkout/coordinator evidence into the pure participant binding;
`execution_finalization.py` owns intent,
continuation and concrete fence-authority stores; `provider_call_recovery.py`
owns provider/detached recovery; checkout/scope modules may return the light
cleanup receipt. `execution_commit.py` imports only light fence/recovery types.
This exact split avoids commit↔finalization and cleanup-owner↔finalization
cycles and is locked by per-symbol ownership and independent import-smoke tests.
The sole exception is PR-4-owned `CheckoutRecoveryRefV2` in
`core/actions/checkout_models.py`; PR-5 imports and extends its recovery behavior
but never moves or redeclares that ref. PR-5 dependency-free
`execution_commit_types.py` alone owns `ExecutionCommitStateV2`,
`ExecutionCommitDecisionBindingV2`, its canonical digest helper and
`ExecutionCommitRecordV2`; `execution_commit.py` owns participant enums,
lifecycle DTOs/protocols and coordinator behavior and imports those pure types.

```python
class InvocationFinalizationIntentPhaseV2(str, Enum):
    CREATED = "created"
    OWNERS_FENCED = "owners_fenced"
    EFFECT_FENCED = "effect_fenced"
    RESULT_COMMITTED = "result_committed"
    CLEANUP_COMPLETE = "cleanup_complete"


@dataclass(frozen=True)
class CancellationRecoveryRefV2:
    reference: str
    revision: int
    root_execution_id: str
    execution_graph_id: str
    token_id: str
    state: Literal["active", "cancel_requested", "cancelled", "completed"]
    cancellation_digest: str


@dataclass(frozen=True)
class CancellationRecoveryRecordV2:
    cancellation_ref: CancellationRecoveryRefV2
    requested_reason_code: str | None
    requested_at_utc: float | None


@dataclass(frozen=True)
class CancellationControllerBindingV2:
    reference: str
    cancellation_revision: int
    token_id: str
    controller_binding_id: str
    binding_digest: str


@dataclass(frozen=True)
class CancellationCompletionReceiptV2:
    cancellation_ref: CancellationRecoveryRefV2
    cleared_controller_binding_ids: tuple[str, ...]
    completion_digest: str


def canonical_cancellation_controller_binding_digest(
    binding: CancellationControllerBindingV2,
) -> str:
    """RFC-8785 cancellation-controller-binding/1.0, excluding own digest."""
    ...


def canonical_cancellation_completion_digest(
    receipt: CancellationCompletionReceiptV2,
) -> str:
    """RFC-8785 cancellation-completion/1.0, excluding own digest."""
    ...


def canonical_cancellation_recovery_record_digest(
    record: CancellationRecoveryRecordV2,
) -> str:
    """Hashes stable identity/revision and all state, excluding own digest."""
    ...


@runtime_checkable
class CancellationRecoveryStoreV2(Protocol):
    def require(
        self,
        reference: CancellationRecoveryRefV2,
    ) -> CancellationRecoveryRecordV2: ...
    def require_current(
        self,
        previous: CancellationRecoveryRefV2,
    ) -> CancellationRecoveryRecordV2: ...
    def require_current_for_graph(
        self,
        *,
        root_execution_id: str,
        execution_graph_id: str,
        token_id: str,
    ) -> CancellationRecoveryRecordV2: ...
    def request_cancel(
        self,
        reference: CancellationRecoveryRefV2,
        *,
        expected_revision: int,
        reason_code: str,
    ) -> CancellationRecoveryRecordV2: ...
    def bind_live_controller(
        self,
        reference: CancellationRecoveryRefV2,
        controller: ExecutorCancellationController,
    ) -> tuple[CancellationRecoveryRecordV2, CancellationControllerBindingV2]: ...
    def unbind_live_controller(
        self,
        binding: CancellationControllerBindingV2,
    ) -> CancellationRecoveryRecordV2: ...
    def acknowledge_cancelled(
        self,
        reference: CancellationRecoveryRefV2,
        *,
        expected_revision: int,
    ) -> CancellationRecoveryRecordV2: ...
    def complete_graph(
        self,
        reference: CancellationRecoveryRefV2,
        *,
        expected_revision: int,
    ) -> CancellationCompletionReceiptV2: ...
    def require_completion(
        self,
        reference: CancellationRecoveryRefV2,
    ) -> CancellationCompletionReceiptV2: ...


@dataclass(frozen=True)
class CancelExecutionRequestV2:
    request_id: str
    execution_id: str
    reason: ExecutionCancellationReasonV2


class ExecutionCancellationReasonV2(str, Enum):
    USER_REQUESTED = "user_requested"
    MISSION_REVOKED = "mission_revoked"
    ADMIN_CONTAINMENT = "admin_containment"


@dataclass(frozen=True)
class ExecutionCancellationReceiptV2:
    request_id: str
    execution_id: str
    cancellation_revision: int
    disposition: Literal[
        "cancel_requested",
        "already_requested",
        "already_completed",
        "too_late_roll_forward",
        "dispatch_already_admitted",
    ]
    receipt_ref: str
    receipt_digest: str


def canonical_execution_cancellation_receipt_digest(
    receipt: ExecutionCancellationReceiptV2,
) -> str:
    """RFC-8785 execution-cancellation-receipt/1.0, excluding own digest."""
    ...


@dataclass(frozen=True)
class ExecutionNoReturnAdmissionBodyV2:
    root_execution_id: str
    execution_graph_id: str
    transaction_id: str
    cancellation_revision: int
    decision_identity_digest: str
    external_effect_participant_id: str | None
    external_effect_registration_digest: str | None

    def __post_init__(self) -> None:
        if (self.external_effect_participant_id is None) != (self.external_effect_registration_digest is None):
            raise ValueError("external_effect_admission_fields_all_or_none")


def canonical_execution_no_return_admission_digest(
    body: ExecutionNoReturnAdmissionBodyV2,
) -> str:
    """RFC-8785 execution-no-return-admission/1.0 over every body field."""
    ...


@dataclass(frozen=True)
class ExecutionNoReturnAdmissionRefV2:
    reference: str
    revision: int
    transaction_id: str
    admission_digest: str


@dataclass(frozen=True)
class ExecutionNoReturnAdmissionReceiptV2:
    admission_ref: ExecutionNoReturnAdmissionRefV2
    body: ExecutionNoReturnAdmissionBodyV2

    def __post_init__(self) -> None:
        if self.admission_ref.transaction_id != self.body.transaction_id:
            raise ValueError("admission_transaction_mismatch")
        if self.admission_ref.admission_digest != (canonical_execution_no_return_admission_digest(self.body)):
            raise ValueError("admission_digest_mismatch")


@runtime_checkable
class ExecutionNoReturnAdmissionStoreV2(Protocol):
    def admit(
        self,
        *,
        cancellation: CancellationRecoveryRecordV2,
        transaction_id: str,
        decision_identity_digest: str,
        external_effect_participant_id: str | None,
        external_effect_registration_digest: str | None,
    ) -> ExecutionNoReturnAdmissionReceiptV2: ...
    def require(
        self,
        reference: ExecutionNoReturnAdmissionRefV2,
    ) -> ExecutionNoReturnAdmissionReceiptV2: ...
    def require_for_transaction(
        self,
        transaction_id: str,
    ) -> ExecutionNoReturnAdmissionReceiptV2 | None: ...


@runtime_checkable
class ExecutionCancellationServiceV2(Protocol):
    def request_cancel(
        self,
        request: CancelExecutionRequestV2,
        *,
        ingress_lease: IngressInvocationLease,
    ) -> ExecutionCancellationReceiptV2: ...


@dataclass(frozen=True)
class ExecutionContinuationRecoveryRefV2:
    reference: str
    revision: int
    parent_execution_id: str
    continuation_kind: Literal["composite_child"]
    handoff_state: Literal["reserved", "custody_transferred", "completed"]
    record_digest: str


@dataclass(frozen=True)
class ExecutionContinuationPendingBindingV2:
    kind: Literal["composite_child"]
    reference: str
    revision: int
    parent_execution_id: str
    binding_digest: str


@dataclass(frozen=True)
class ExecutionContinuationRecoveryRecordV2:
    continuation_ref: ExecutionContinuationRecoveryRefV2
    pending: ExecutionContinuationPendingBindingV2
    intent_ref: InvocationFinalizationIntentRefV2
    checkout_ref: CheckoutRecoveryRefV2 | None
    scope_ref: InvocationScopeRecoveryRefV2 | None
    coordinator_ref: ExecutionCommitRecoveryRefV2 | None
    graph_ref: ApprovalGraphRecoveryRefV2 | None
    final_report_ref: str | None
    final_report_digest: str | None


def canonical_execution_continuation_recovery_record_digest(
    record: ExecutionContinuationRecoveryRecordV2,
) -> str:
    """Hashes stable identity/revision and all state, excluding own digest."""
    ...


@dataclass(frozen=True)
class ExecutionContinuationCompletionReceiptV2:
    continuation_ref: ExecutionContinuationRecoveryRefV2
    final_report_ref: str
    final_report_digest: str
    intent_ref: InvocationFinalizationIntentRefV2
    completion_digest: str


@runtime_checkable
class ExecutionContinuationRecoveryStoreV2(Protocol):
    def reserve_handoff(
        self,
        *,
        pending: ExecutionContinuationPendingBindingV2,
        intent_ref: InvocationFinalizationIntentRefV2,
    ) -> ExecutionContinuationRecoveryRecordV2: ...
    def mark_custody_transferred(
        self,
        reference: ExecutionContinuationRecoveryRefV2,
        *,
        expected_revision: int,
        checkout_ref: CheckoutRecoveryRefV2,
        scope_ref: InvocationScopeRecoveryRefV2,
        coordinator_ref: ExecutionCommitRecoveryRefV2,
        graph_ref: ApprovalGraphRecoveryRefV2,
    ) -> ExecutionContinuationRecoveryRecordV2: ...
    def require(
        self,
        reference: ExecutionContinuationRecoveryRefV2,
    ) -> ExecutionContinuationRecoveryRecordV2: ...
    def list_incomplete(self) -> tuple[ExecutionContinuationRecoveryRefV2, ...]: ...
    def complete(
        self,
        reference: ExecutionContinuationRecoveryRefV2,
        *,
        expected_revision: int,
        final_report: ActionExecutionReportEnvelopeV2,
        intent: InvocationFinalizationIntentRecordV2,
    ) -> ExecutionContinuationCompletionReceiptV2: ...


@dataclass(frozen=True)
class PrimaryExecutionOutcomeSnapshotV2:
    status: ExecutionStatusV2
    reason_codes: tuple[str, ...]
    outcome_digest: str


@dataclass(frozen=True)
class ReportPublicationCheckpointV2:
    expected_previous_revision: int | None
    publication_idempotency_key: str
    report_digest: str


@dataclass(frozen=True)
class ExternalEffectRegistrationIdentityV2:
    transaction_id: str
    participant_id: str
    registration_digest: str


@dataclass(frozen=True)
class EffectDispatchAuthorizationV2:
    transaction_id: str
    external_effect_registration_identity: ExternalEffectRegistrationIdentityV2
    reversible_prepare_set_digest: str
    no_return_admission_ref: ExecutionNoReturnAdmissionRefV2
    no_return_admission_digest: str
    coordinator_revision: int
    authorization_digest: str


@dataclass(frozen=True)
class PreparedFinalizationSnapshotV2:
    record: InvocationFinalizationRecordV2
    finalization_digest: str
    cleanup_receipts: tuple[RecoveryOwnerCleanupReceiptV2, ...]
    cleanup_receipt_set_digest: str
    persistence_outcome: FinalizationPersistenceOutcomeV2 | None


@dataclass(frozen=True)
class InvocationLeaseRecoveryRefV2:
    lease_id: str
    lease_revision: int
    lease_digest: str


@dataclass(frozen=True)
class ApprovalGraphRecoveryRefV2:
    graph_id: str
    graph_revision: int
    owner: bool
    graph_digest: str


@dataclass(frozen=True)
class AttemptLeaseRecoveryRefV2:
    attempt_group_id: str
    lease_id: str
    lease_revision: int
    state: AttemptLeaseState
    lease_digest: str


class ProviderCallRecoveryStateV2(str, Enum):
    RESERVED = "reserved"
    RUNNING = "running"
    QUIESCED = "quiesced"
    IPC_CLOSED = "ipc_closed"
    CHILD_COMPLETED = "child_completed"
    DETACHED_FENCED = "detached_fenced"


@dataclass(frozen=True)
class ProviderCallRecoveryRefV2:
    call_id: str
    call_revision: int
    execution_mode: ProviderExecutionModeV2
    state: ProviderCallRecoveryStateV2
    runner_handle_ref: str | None
    record_digest: str


@dataclass(frozen=True)
class ProviderCallRecoveryRecordV2:
    recovery_ref: ProviderCallRecoveryRefV2
    execution_id: str
    action_id: str
    phase: ProviderCallPhaseV2
    provider_id: str
    mount_revision: int
    mount_digest: str
    provider_generation: str
    snapshot_digest: str
    call_plan_digest: str
    runner_handle_ref: str | None
    closure_receipt: ProviderBoundaryClosureReceiptV2 | None
    detached_record_ref: DetachedProviderCallRefV2 | None


@dataclass(frozen=True)
class InvocationFinalizationIntentBodyV2:
    execution_id: str
    action_id: str
    transaction_id: str
    phase: InvocationFinalizationIntentPhaseV2
    ingress_recovery_ref: InvocationLeaseRecoveryRefV2
    cancellation_recovery_ref: CancellationRecoveryRefV2
    continuation_recovery_ref: ExecutionContinuationRecoveryRefV2 | None
    approval_graph_recovery_ref: ApprovalGraphRecoveryRefV2 | None
    attempt_recovery_ref: AttemptLeaseRecoveryRefV2 | None
    checkout_recovery_ref: CheckoutRecoveryRefV2 | None
    scope_recovery_ref: InvocationScopeRecoveryRefV2 | None
    coordinator_recovery_ref: ExecutionCommitRecoveryRefV2 | None
    provider_call_recovery_ref: ProviderCallRecoveryRefV2 | None
    effect_dispatch_authorization: EffectDispatchAuthorizationV2 | None
    primary_outcome: PrimaryExecutionOutcomeSnapshotV2 | None
    prepared_finalization: PreparedFinalizationSnapshotV2 | None
    report_publication: ReportPublicationCheckpointV2 | None


@dataclass(frozen=True)
class InvocationFinalizationIntentRecordV2:
    intent_ref: InvocationFinalizationIntentRefV2
    body: InvocationFinalizationIntentBodyV2


@dataclass(frozen=True)
class InvocationFinalizationIntentCheckpointV2:
    expected_revision: int
    phase: InvocationFinalizationIntentPhaseV2
    ingress_recovery_ref: InvocationLeaseRecoveryRefV2
    cancellation_recovery_ref: CancellationRecoveryRefV2
    continuation_recovery_ref: ExecutionContinuationRecoveryRefV2 | None
    approval_graph_recovery_ref: ApprovalGraphRecoveryRefV2 | None
    attempt_recovery_ref: AttemptLeaseRecoveryRefV2 | None
    checkout_recovery_ref: CheckoutRecoveryRefV2 | None
    scope_recovery_ref: InvocationScopeRecoveryRefV2 | None
    coordinator_recovery_ref: ExecutionCommitRecoveryRefV2 | None
    provider_call_recovery_ref: ProviderCallRecoveryRefV2 | None
    effect_dispatch_authorization: EffectDispatchAuthorizationV2 | None
    primary_outcome: PrimaryExecutionOutcomeSnapshotV2 | None
    prepared_finalization: PreparedFinalizationSnapshotV2 | None
    report_publication: ReportPublicationCheckpointV2 | None


def canonical_primary_execution_outcome_digest(
    outcome: PrimaryExecutionOutcomeSnapshotV2,
) -> str:
    """Hashes status/reason_codes only; excludes outcome_digest itself."""
    ...


def canonical_finalization_intent_digest(
    record: InvocationFinalizationIntentRecordV2,
) -> str:
    """Hashes intent ref identity/revision plus body; excludes only ref digest."""
    ...


def canonical_action_execution_report_digest(
    report: ActionExecutionReportV2,
) -> str: ...


@dataclass(frozen=True)
class InvocationFinalizationIntentRefV2:
    reference: str
    revision: int
    execution_id: str
    action_id: str
    transaction_id: str
    intent_digest: str


@dataclass(frozen=True)
class InvocationFinalizationIntentCompletionReceiptV2:
    intent_ref: InvocationFinalizationIntentRefV2
    persistence_outcome_digest: str
    report_ref: str
    report_revision: int
    report_digest: str
    completion_digest: str


def canonical_finalization_intent_completion_digest(
    receipt: InvocationFinalizationIntentCompletionReceiptV2,
) -> str:
    """finalization-intent-completion/1.0; exact intent ref, canonical
    persistence-outcome digest and report ref/revision/digest; excludes only
    completion_digest."""
    ...


@runtime_checkable
class InvocationFinalizationIntentStoreV2(Protocol):
    def checkpoint(
        self,
        intent: InvocationFinalizationIntentRecordV2,
        update: InvocationFinalizationIntentCheckpointV2,
    ) -> InvocationFinalizationIntentRecordV2: ...
    def require(
        self,
        reference: InvocationFinalizationIntentRefV2,
    ) -> InvocationFinalizationIntentRecordV2: ...
    def require_current(
        self,
        stable_reference: str,
    ) -> InvocationFinalizationIntentRecordV2: ...
    def complete(
        self,
        intent_ref: InvocationFinalizationIntentRefV2,
        outcome: FinalizationPersistenceOutcomeV2,
        report: ActionExecutionReportEnvelopeV2,
    ) -> InvocationFinalizationIntentCompletionReceiptV2: ...
    def require_completion(
        self,
        intent_ref: InvocationFinalizationIntentRefV2,
    ) -> InvocationFinalizationIntentCompletionReceiptV2: ...
    def list_pending(self) -> tuple[InvocationFinalizationIntentRecordV2, ...]: ...


@dataclass(frozen=True)
class ExecutionCreationRefV2:
    reference: str
    revision: int
    execution_id: str
    transaction_id: str
    creation_digest: str


@dataclass(frozen=True)
class ExecutionCreationReceiptV2:
    creation_ref: ExecutionCreationRefV2
    intent: InvocationFinalizationIntentRecordV2
    ownership_ref: ExecutionReportOwnershipRefV2
    cancellation_controller_binding: CancellationControllerBindingV2 | None


def canonical_execution_creation_digest(
    *,
    intent: InvocationFinalizationIntentRecordV2,
    ownership_ref: ExecutionReportOwnershipRefV2,
    cancellation_controller_binding: CancellationControllerBindingV2 | None,
) -> str:
    """execution-creation/1.0 over exact intent ref identity/revision/digest,
    ownership ref identity/revision/digest and nullable controller-binding
    identity/digest."""
    ...


@runtime_checkable
class ExecutionCreationStoreV2(Protocol):
    def begin_root(
        self,
        *,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        ingress_lease: IngressInvocationLease,
        cancellation_controller: ExecutorCancellationController,
        ownership: ExecutionReportOwnershipBindingV2,
        idempotency_key: str,
    ) -> ExecutionCreationReceiptV2: ...
    def begin_child(
        self,
        *,
        execution_id: str,
        action_id: str,
        transaction_id: str,
        ingress_lease: ChildIngressLease,
        root_execution_id: str,
        execution_graph_id: str,
        inherited_token_id: str,
        ownership: ExecutionReportOwnershipBindingV2,
        idempotency_key: str,
    ) -> ExecutionCreationReceiptV2: ...
    def require(
        self,
        reference: ExecutionCreationRefV2,
    ) -> ExecutionCreationReceiptV2: ...


TRecoverableOwnerV2 = TypeVar("TRecoverableOwnerV2")
TRecoveryRefV2 = TypeVar("TRecoveryRefV2")
TRecoveryCreationSpecV2 = TypeVar("TRecoveryCreationSpecV2")


@runtime_checkable
class IntentBoundRecoverableOwnerFactoryV2(
    Protocol[TRecoverableOwnerV2, TRecoveryRefV2, TRecoveryCreationSpecV2],
):
    def reserve_inert(
        self,
        *,
        intent: InvocationFinalizationIntentRecordV2,
        creation_spec: TRecoveryCreationSpecV2,
        creation_spec_digest: str,
    ) -> TRecoveryRefV2: ...
    def activate_after_intent_checkpoint(
        self,
        *,
        recovery_ref: TRecoveryRefV2,
        intent: InvocationFinalizationIntentRecordV2,
    ) -> TRecoverableOwnerV2: ...
    def list_orphan_inert_reservations(self) -> tuple[TRecoveryRefV2, ...]: ...
    def reclaim_inert(
        self,
        recovery_ref: TRecoveryRefV2,
    ) -> CleanupHandlerReceiptV2: ...


@dataclass(frozen=True)
class CheckoutOwnerCreationSpecV2:
    request: ExecutorCheckoutRequestBundle
    request_digest: str


@dataclass(frozen=True)
class InvocationScopeCreationSpecV2:
    execution_id: str
    transaction_id: str
    cleanup_registry_revision: int
    spec_digest: str


@dataclass(frozen=True)
class ApprovalGraphCreationSpecV2:
    root_action_id: str
    execution_graph_id: str
    approval_ref: str | None
    approval_revision: int | None
    spec_digest: str


@dataclass(frozen=True)
class AttemptReservationCreationSpecV2:
    graph_recovery_ref: ApprovalGraphRecoveryRefV2
    attempt_group_id: str
    concrete_action_id: str
    spec_digest: str


@runtime_checkable
class IntentBoundCheckoutOwnerFactoryV2(
    IntentBoundRecoverableOwnerFactoryV2[
        ExecutorCheckoutBundle,
        CheckoutRecoveryRefV2,
        CheckoutOwnerCreationSpecV2,
    ],
    Protocol,
): ...


@runtime_checkable
class IntentBoundInvocationScopeFactoryV2(
    IntentBoundRecoverableOwnerFactoryV2[
        InvocationScope,
        InvocationScopeRecoveryRefV2,
        InvocationScopeCreationSpecV2,
    ],
    Protocol,
): ...


@runtime_checkable
class IntentBoundApprovalGraphFactoryV2(
    IntentBoundRecoverableOwnerFactoryV2[
        ApprovalExecutionLease,
        ApprovalGraphRecoveryRefV2,
        ApprovalGraphCreationSpecV2,
    ],
    Protocol,
): ...


@runtime_checkable
class IntentBoundAttemptLeaseFactoryV2(
    IntentBoundRecoverableOwnerFactoryV2[
        ApprovalAttemptLease,
        AttemptLeaseRecoveryRefV2,
        AttemptReservationCreationSpecV2,
    ],
    Protocol,
): ...


@dataclass(frozen=True)
class RecoveryOwnerCleanupReceiptV2:
    owner_kind: Literal["ingress", "approval_graph", "attempt", "checkout", "scope"]
    owner_reference: str
    before_revision: int
    after_revision: int
    idempotency_key: str
    disposition: Literal[
        "consumed",
        "closed",
        "released",
        "not_required",
        "already_done",
    ]
    operation_attempt_id: str
    receipt_ref: str
    receipt_digest: str


def canonical_recovery_owner_cleanup_receipt_digest(
    receipt: RecoveryOwnerCleanupReceiptV2,
) -> str: ...


def canonical_cleanup_receipt_set_digest(
    receipts: tuple[RecoveryOwnerCleanupReceiptV2, ...],
) -> str:
    """Hashes unique receipts sorted by (owner_kind, owner_reference)."""
    ...


@runtime_checkable
class InvocationLeaseRecoveryStoreV2(Protocol):
    def require_current_ref(
        self,
        ref: InvocationLeaseRecoveryRefV2,
    ) -> InvocationLeaseRecoveryRefV2: ...
    def reopen_and_consume(
        self,
        ref: InvocationLeaseRecoveryRefV2,
        operation: CleanupOperationContextV2,
    ) -> RecoveryOwnerCleanupReceiptV2: ...


@runtime_checkable
class ApprovalGraphRecoveryStoreV2(Protocol):
    def require_current_ref(
        self,
        ref: ApprovalGraphRecoveryRefV2,
    ) -> ApprovalGraphRecoveryRefV2: ...
    def reopen_and_close_if_owner(
        self,
        ref: ApprovalGraphRecoveryRefV2,
        operation: CleanupOperationContextV2,
    ) -> RecoveryOwnerCleanupReceiptV2: ...


@runtime_checkable
class AttemptLeaseRecoveryStoreV2(Protocol):
    def require_current_ref(
        self,
        ref: AttemptLeaseRecoveryRefV2,
    ) -> AttemptLeaseRecoveryRefV2: ...
    def reopen_and_release_if_pending(
        self,
        ref: AttemptLeaseRecoveryRefV2,
        operation: CleanupOperationContextV2,
    ) -> RecoveryOwnerCleanupReceiptV2: ...


@runtime_checkable
class ProviderCallRecoveryJournalV2(Protocol):
    def reserve(
        self,
        *,
        call_plan: ProviderPhaseCallPlanV2,
    ) -> ProviderCallRecoveryRecordV2: ...
    def transition(
        self,
        record: ProviderCallRecoveryRecordV2,
        *,
        state: ProviderCallRecoveryStateV2,
        runner_handle_ref: str | None,
        closure_receipt: ProviderBoundaryClosureReceiptV2 | None,
        detached_record_ref: DetachedProviderCallRefV2 | None,
    ) -> ProviderCallRecoveryRecordV2: ...
    def require(
        self,
        ref: ProviderCallRecoveryRefV2,
    ) -> ProviderCallRecoveryRecordV2: ...
    def probe_and_reconcile(
        self,
        ref: ProviderCallRecoveryRefV2,
        *,
        runner_registry: ProviderRunnerRegistryV2,
        operation: ParticipantOperationContextV2,
    ) -> ProviderCallRecoveryRecordV2: ...
    def list_nonterminal(self) -> tuple[ProviderCallRecoveryRefV2, ...]: ...
```

Provider-call recovery is a mandatory journaled owner, not optional prose. The
executor calls `reserve(call_plan)`, CAS-attaches the returned RESERVED ref to
the intent, then transitions it to RUNNING before the runner may invoke provider
code. Detachable execution modes must already have a stable runner handle at
RUNNING. The boundary owns an injected journal, accepts the exact read-back
record, verifies every call-plan/mount/provider/snapshot field, and after lease
closure durably transitions it to a quiesced terminal state or the explicit
recoverable `DETACHED_FENCED` state before returning or raising.
`DETACHED_FENCED` additionally binds the store-minted detached-record
ref. Only `probe_and_reconcile()` may advance a detached journal entry after
restart. `ProviderCallTerminationStoreV2.list_reconcilable()` independently
enumerates every `WAITING_QUIESCENCE|QUIESCED|RECONCILING` detached record, so
the recoverable runner `DETACHED_FENCED` evidence remains startup-discoverable. A
matching probe CASes the detached store to QUIESCED and the call journal from
DETACHED_FENCED to QUIESCED; unknown handles or mismatched closure digests remain
pending. Every transition
is expected-revision CAS, identical digest replay is idempotent, and terminal
states cannot regress.

`ExecutionCreationStoreV2.begin_root()` accepts the authenticated root ingress
lease plus the exact internal controller from the root authority bundle (never
a structural caller token), derives its read-only token, and atomically creates/
read-backs the graph-scoped cancellation row and ingress recovery ref,
the cancellation recovery row bound to the live executor controller, the
CREATED intent and immutable report-ownership binding in one durable store
transaction. The cancellation store's create method is a private component call
valid only inside that transaction; it is not a second public creation path.
`begin_child()` accepts a child ingress lease plus the stable root/graph/token
identity from its lineage/budget, calls `require_current_for_graph()` and
creates no second cancellation row. Recovery can always
authorize a query even if the next instruction crashes. The store alone mints
`ExecutionCreationRefV2`; it recomputes the domain-tagged canonical creation
digest over the intent/ownership/controller-binding identities and requires an idempotency key
derived from authenticated request/execution/transaction identity. Same key and
digest returns the identical receipt, conflicting replay fails, and recovery
starts with `require(creation_ref)` rather than caller-assembled DTOs.
The root receipt carries the exact store-issued
`CancellationControllerBindingV2`; a child receipt carries `None` because it
shares the root controller/token and creates no binding. Root creation replay
returns the same binding, never a duplicate. A terminal root unbinds that
binding before graph-owner `complete_graph()`. A progress/continuation handoff
unbinds the outgoing live controller only after custody is durable; the
reconciler later creates and binds its own controller as described below.
Every cancel request first CASes `CancellationRecoveryStoreV2`, then signals all
bound live controllers; startup/rebind uses `require_current(previous_ref)`
to discover a newer revision and never treats a stale ACTIVE snapshot as
authority. A composite recovery budget is issued only after current ACTIVE is
read, a private controller for the stable token ID is created, and
`bind_live_controller(current_ref, controller)` atomically rechecks revision/
state. If cancellation raced, binding signals/fails immediately. The budget
uses only that controller's token and state is rechecked once more immediately
before VERIFY. CANCEL_REQUESTED/CANCELLED is terminal for resume and produces a
contained parent CANCELLED path without VERIFY/provider re-entry. Every
live/recovery finally unbinds its store-issued controller binding. Only the
graph owner, after all children/continuations are terminal, CASes
`complete_graph()`; COMPLETED clears every controller binding, rejects later
signal delivery and makes authenticated cancel return `already_completed`.
Finish-vs-cancel is resolved by one store CAS, so controllers cannot leak or
receive cancellation after graph completion.
All controller-binding/cancellation/completion receipts use the domain-tagged
canonical helpers above, exclude only their own digest and must match the same
root/graph/token identity and monotonic revision. `complete_graph()` persists
the receipt; identical replay/`require_completion()` returns it, while any
changed binding set or status is rejected. Golden/tamper vectors cover every
digest field set.
The only public cancellation ingress is
`ExecutionCancellationServiceV2.request_cancel()`. It consumes a fresh ingress
lease in `finally`, requires `lease.bound_request_id == request.request_id`,
non-enumeratingly resolves execution ownership/mission and the creation record,
authorizes the subject, then resolves the current graph-scoped cancellation row
server-side. Callers never receive or submit its opaque ref. The service CASes
the durable request before signalling every current binding and returns a
store-issued idempotent receipt; wrong mission/subject, stale ownership, unknown
execution and conflicting replay fail without revealing which check failed.
The durable cancellation-vs-commit/effect cutoff is
`ExecutionNoReturnAdmissionStoreV2.admit()`, not eventual token signalling. After
successful verify and immediately before effect authorization or
`decide_commit()`, executor CASes the current graph cancellation revision with
the exact transaction/decision/effect identity. If cancel won first, admission
fails and the transaction aborts/CANCELLED before dispatch. If admission won first,
its store-issued ref and canonical digest are read back and included in
`EffectDispatchAuthorizationV2` and the commit decision digest; both
`dispatch_terminal_effect(operation, admission)` and
`decide_commit(admission)` reject a different transaction, graph, current
cancellation revision, effect registration or decision identity. The
no-`EXTERNAL_EFFECT` path treats admission as its commit cutoff:
`decide_commit(admission)` durably binds it and must roll forward, and later
public cancel returns `too_late_roll_forward`. On the terminal-effect path,
admission linearizes cancellation against dispatch but is not proof that the
effect succeeded: a later cancel returns `dispatch_already_admitted` and may
request containment, while `EFFECT_CONFIRMED` forces commit/roll-forward,
`FAILED_NO_EFFECT` permits `ABORT_DECIDED`, and `IN_DOUBT` remains probe-only
with custody preserved. Cancellation never interrupts or repeats an admitted
dispatch. `require_for_transaction()` recovers a crash after admission before
the coordinator decision without rerunning the race. Same-key/same-body replay
returns the same ref; conflicting decision/effect identity fails. Same-store CAS
or an equivalent serializable transaction is required.
Approval graph, attempt and provider-call refs are then attached monotonically
as those owners appear; checkout/scope/coordinator refs are absent iff that
owner never existed.
Those `begin_root()`/`begin_child()` calls are the first durable execution write
and return a CREATED record
with null owner/outcome/publication fields. To eliminate the create→attach crash
window, each checkout/scope/coordinator/approval-graph/attempt factory follows
the exact three-step
protocol: reserve an inert durable recovery record, CAS its ref into the full
desired intent snapshot, then activate/open and return the live owner. There is
no public direct owner constructor. A crash before attachment leaves only an
inert record found and reclaimed by `list_orphan_inert_reservations()`; a crash
after attachment is recovered through the intent. Effect dispatch and result
visibility require the matching owner checkpoint. Every checkpoint returns a
read-back store record; same-digest replay is idempotent and revision conflicts
fail. Once the primary outcome is known, its status/reasons/digest are
checkpointed. At CLEANUP_COMPLETE the factory-produced finalization record and
its canonical digest are checkpointed before `persist_or_enqueue`; its durable
persistence outcome is then CAS-attached. A crash before this checkpoint may
use `cleanup_outcome_unknown`; a crash after it must replay the exact stored
cleanup/errors/status and digest. Before final publication the exact previous revision,
idempotency key and report digest are checkpointed, so restart can replay the
same CAS. The intent does not predict a future committed marker: recovery
resolves current transaction state through `coordinator_recovery_ref` and the
store-issued marker API. Completion order is exact:
finalization persisted or retry-UNBOUND enqueued → idempotent `publish_final` →
when enqueued, `bind_pending_publication()` →
`intent_store.complete(intent_ref, outcome, same_report_envelope)`. A crash
between publish and complete replays the same publication key/ref and then
completes; identity/digests across all three records must match.
Checkpoint updates are full desired snapshots, not nullable patches: a field
that was non-null can never become null or change identity. Phase ordering uses
the explicit rank table `CREATED=0, OWNERS_FENCED=1, EFFECT_FENCED=2,
RESULT_COMMITTED=3, CLEANUP_COMPLETE=4`, not Enum comparison. Rank may stay the
same for monotonic field attachment or increase; it never decreases. Allowed
skips are CREATED→OWNERS_FENCED for an owner-free denial,
OWNERS_FENCED→CLEANUP_COMPLETE for a pre-effect failure, and
OWNERS_FENCED→RESULT_COMMITTED only when the durable coordinator participant
set proves zero EXTERNAL_EFFECT registrations, and
EFFECT_FENCED→CLEANUP_COMPLETE when an effect path produces no result.
EFFECT_FENCED is never synthesized for the no-effect path because its
authorization must name a real external-effect registration. RESULT_COMMITTED always
precedes CLEANUP_COMPLETE. `record.intent_ref` is the sole ref accepted by
`require`, `checkpoint` and `complete` at that exact revision.
`canonical_finalization_intent_digest()` hashes the domain/version-tagged
RFC-8785 object `{reference, revision, execution_id, action_id, transaction_id,
body}`; the nested `intent_ref.intent_digest` is the sole omitted member, and
the duplicated identity values in the ref and body must match. The other
canonical digest helpers likewise exclude only their own digest field. Intent
checkpoint/complete and report
publication recompute them; a caller-supplied mismatch fails closed.
Recovery reopens every ref present in the record. It first proves a provider
call QUIESCED or preserves a DETACHED_FENCED owner, then releases only a PENDING
attempt, resumes the coordinator decision, closes checkout/scope, closes the
approval graph only when this execution is its owner, and finally consumes the
ingress lease. Each release/close/consume call is bounded by
`CleanupOperationContextV2`, returns an idempotent durable
`RecoveryOwnerCleanupReceiptV2`, and its digest is included in the prepared
finalization snapshot before CLEANUP_COMPLETE. Missing or mismatched recovery evidence leaves the intent pending
and never guesses cleanup completion.

### 8.7. Approval use semantics

Approval use is consumed at concrete provider attempt start, not after success.

Использовать только:

```text
attempt_factory.reserve_inert(...) → intent CAS →
attempt_factory.activate_after_intent_checkpoint(...) → PENDING attempt_lease
attempt_lease.start(...)
```

Semantics:

```text
only the factory implementation may call underlying graph.reserve_attempt;
the executor cannot call it directly
factory activation creates PENDING lease and does not decrement remaining_uses
start atomically performs PENDING → STARTED and decrements remaining_uses
release_before_start performs PENDING → RELEASED
STARTED use is never restored after provider failure, timeout, cancellation or late commit failure
router parent calls authorize_router_step and consumes zero uses
```

Legacy approval attempt/commit aliases не существуют в canonical API.

### 8.8. Status precedence

```text
CANCELLED + cleanup failure → CANCELLED
TIMED_OUT + cleanup failure → TIMED_OUT
FAILED + cleanup failure    → FAILED
SUCCEEDED + cleanup failure → PARTIAL with reason code `invocation_cleanup_failed`
PARTIAL + cleanup failure   → PARTIAL
```

## 8.9. Execution budget, cancellation, provider staging and child lineage

Executor-owned non-serializable models:

```python
@dataclass(frozen=True)
class ExecutionBudget:
    absolute_deadline_monotonic: float
    max_output_bytes: int
    max_child_depth: int
    cancellation_token: CancellationToken


@dataclass(frozen=True)
class ExecutionLineage:
    root_execution_id: str
    parent_execution_id: str | None
    execution_graph_id: str
    child_depth: int
```

A child keeps the same cancellation token and execution graph, receives a new
request/execution ID, increments depth, and can only narrow deadline/output/depth.

PR-5 defines only PR-5 foundation staging types:

```python
@dataclass(frozen=True)
class NonSensitiveObservationStageRequestV2:
    observation_schema_id: str
    expected_payload_digest: str
    payload: bytes = field(repr=False, compare=False)


@dataclass(frozen=True)
class StagedObservationNormalizationV2:
    observation: StagedObservationV2
    fact_drafts: tuple[FactDraftRefV2, ...]
    fact_registration_refs: tuple[ParticipantRegistrationRefV2, ...]


@dataclass(frozen=True)
class StagedObservationV2:
    observation_draft_ref: ObservationDraftRefV2
    registration_ref: ParticipantRegistrationRefV2


@dataclass(frozen=True)
class NonSensitiveArtifactStageRequestV2:
    transient_id: str
    artifact_kind: ArtifactKind
    expected_content_digest: str
    expected_size: int
    media_type: str
    target: str | None


@dataclass(frozen=True)
class SensitiveArtifactStageRequestV2:
    transient_id: str
    artifact_kind: ArtifactKind
    expected_size: int
    media_type: str
    target: str | None


ArtifactStageRequestV2: TypeAlias = NonSensitiveArtifactStageRequestV2 | SensitiveArtifactStageRequestV2


@dataclass(frozen=True)
class StagedArtifactV2:
    artifact_draft_ref: ArtifactDraftRefV2
    registration_ref: ParticipantRegistrationRefV2


@dataclass(frozen=True)
class ManagedResourceStageRequestV2:
    transient_id: str
    resource_kind: ManagedResourceKind
    target: str | None
    lifecycle_owner: str
    close_action_id: str | None
    expires_at: float | None


@dataclass(frozen=True)
class ParticipantPayloadStageRequestV2:
    payload_schema_id: str
    expected_payload_digest: str
    canonical_payload: bytes = field(repr=False, compare=False)


@dataclass(frozen=True)
class StagedParticipantPayloadV2:
    payload_draft_ref: ParticipantPayloadDraftRefV2
    registration_ref: ParticipantRegistrationRefV2


@runtime_checkable
class ProviderStagingFacade(Protocol):
    @property
    def transaction_id(self) -> str: ...

    def stage_observation(
        self,
        request: NonSensitiveObservationStageRequestV2,
    ) -> StagedObservationNormalizationV2: ...

    def stage_artifact(
        self,
        request: ArtifactStageRequestV2,
    ) -> StagedArtifactV2: ...

    def stage_managed_resource(
        self,
        request: ManagedResourceStageRequestV2,
    ) -> StagedManagedResourceV2: ...

    def stage_participant_payload(
        self,
        request: ParticipantPayloadStageRequestV2,
    ) -> StagedParticipantPayloadV2: ...
```

PR-5 deliberately does not mention `C2ArtifactBuildOutput`,
`C2ArtifactStageRequestV1`, `StagedC2Artifact`, `V2InputUnion` or concrete PR-7
result variants. PR-6, after it creates the exact C2 build/stage DTO, modifies
the same protocol with one additional method:

```python
def stage_c2_artifact(
    self,
    request: C2ArtifactStageRequestV1,
) -> C2ArtifactStageReceiptV1: ...
```

All V2 execute calls receive one executor-built context:

```python
@dataclass(frozen=True, repr=False)
class BoundProviderInvocationContext:
    materials: BoundMaterialBundle
    scope: ProviderInvocationScopeV2 = field(repr=False, compare=False)
    staging: ProviderStagingFacade = field(repr=False, compare=False)
    participants: ProviderParticipantRegistrationFacade = field(
        repr=False,
        compare=False,
    )
    sensitive_handles: SensitiveObservationHandleFactoryV2 = field(
        repr=False,
        compare=False,
    )
    phase_lease: ProviderExecutePhaseLeaseV2 = field(repr=False, compare=False)
    transaction_id: str
    budget: ExecutionBudget
    lineage: ExecutionLineage
```

Mandatory invariants:

```text
context.transaction_id == context.staging.transaction_id
context.transaction_id == context.participants.transaction_id
context.phase_lease is the same lease checked by every provider-visible
material/scope/staging/participant/factory capability
all draft/registration refs use the same transaction ID
materials belong to the current fenced checkout
provider can stage/register only through the restricted facades
provider has no participant lifecycle or coordinator method
provider context has no sensitive staging capability, private InvocationScope,
ResourceOwner, store, C2 control client or global service locator
```

Every staging implementation recomputes digest, byte size and count from the
actual payload/transient/mutable source and compares them with expected
metadata. It canonical-encodes participant payloads itself and returns only
store-owned draft/registration refs. Provider-claimed digest/size/count are
never authoritative. Mismatch closes/zeroizes/deletes the transient and fails
before participant prepare. This invariant applies to observations, ordinary
artifacts, participant payloads, sensitive batches and C2 artifacts.

For `SensitiveArtifactStageRequestV2` the provider supplies no integrity tag:
only the executor/store owns the HMAC capability. The stager streams the
transient once, computes the authoritative keyed tag and sealed-record digest,
while the ArtifactStore-owned `SensitiveArtifactEnvelopeWriterV2` encrypts each
chunk and returns a seal receipt. HMAC tag, seal receipt, draft and participant
registration commit atomically; abort destroys the wrapping key and marks the
envelope revoked. It checks size/type/target and returns integrity/envelope
metadata only in
`SensitiveArtifactDraftRefV2`. The non-sensitive branch instead recomputes and
compares the caller's expected public content digest.

For artifact methods the facade uses only the private
`ArtifactTransientResolverV2.claim_owned_for_staging(scope, transient_id)`.
The resolved object must satisfy `ReadableArtifactTransientV2`, belong to the
current scope and still be unclaimed. For a non-sensitive request the internal
sink computes public SHA-256 and byte count. For a sensitive request it HMACs
plaintext while sealing/encrypting, computes public SHA-256 only over the
ciphertext/envelope and never hashes plaintext with an unkeyed digest. Provider
code never supplies a filesystem path or obtains the sink/resolver. Successful
acceptance, ownership transfer and participant registration are one transaction.
Digest/size mismatch, second claim, wrong scope, early close or stream failure
invalidates the provisional record and leaves/returns ownership for cleanup.
An artifact-producing reviewed backend deposits its executor-private
`ReadableArtifactTransientV2` into `OwnedTransientRegistryV2` and returns only a
store-issued `BackendOwnedTransientReceiptV2`. Provider/builder code passes that
receipt to `ProviderInvocationScopeV2.register_transient()`, receives a
`PhaseBoundTransientRefV2`, and passes only that ref/ID to staging. It never
receives the readable object or raw handle. Registration failure leaves the
registry-owned object on its recoverable cleanup path; successful staging
atomically invalidates the phase-bound ref while moving the private capsule.

Observation staging has one owner as well. The executor-owned observation
normalizer decodes the closed observation schema, stages zero or more exact
`FactDraftRefV2` records with FACT registrations, and atomically registers an
OBSERVATION aggregator depending on those registrations. It returns
`StagedObservationNormalizationV2`; `NO_FACT` is a durable aggregator receipt,
not a second FactStore writer. Provider results carry its `.observation` view,
while the executor staging snapshot retains the fact and registration evidence
for result dependencies. ObservationStore never writes FactStore behind an
undeclared participant.

PR-5 execution boundary uses only foundation protocols:

```python
TRequestV2_contra = TypeVar("TRequestV2_contra", contravariant=True)
TProviderResultV2_co = TypeVar(
    "TProviderResultV2_co",
    bound=ProviderResultFoundationV2,
    covariant=True,
)


@runtime_checkable
class BoundProviderCallableV2(
    Protocol[TRequestV2_contra, TProviderResultV2_co],
):
    def execute_bound(
        self,
        request: TRequestV2_contra,
        invocation: BoundProviderInvocationContext,
    ) -> TProviderResultV2_co: ...


@dataclass(frozen=True)
class ProviderPhaseCallPlanV2:
    call_id: str
    execution_id: str
    action_id: str
    phase: ProviderCallPhaseV2
    provider_id: str
    provider_transport: ProviderTransport
    execution_mode: ProviderExecutionModeV2
    mount_revision: int
    mount_digest: str
    probe_version: str
    provider_generation: str
    daemon_instance_id: str | None
    snapshot_digest: str
    absolute_deadline_monotonic: float
    plan_digest: str


class ProviderCallPhaseV2(str, Enum):
    CHECK = "check"
    EXECUTE = "execute"
    ROUTE = "route"
    VERIFY = "verify"


def canonical_provider_phase_call_plan_digest(
    plan: ProviderPhaseCallPlanV2,
) -> str:
    """Canonical schema-tagged digest excluding plan_digest itself."""
    ...


class ProviderCallBoundary:
    _recovery_journal: ProviderCallRecoveryJournalV2

    def invoke_execute(
        self,
        adapter: BoundProviderCallableV2[TRequestV2_contra, TProviderResultV2_co],
        request: TRequestV2_contra,
        invocation: BoundProviderInvocationContext,
        *,
        call_plan: ProviderPhaseCallPlanV2,
        call_record: ProviderCallRecoveryRecordV2,
        _phase_controller: _ProviderExecutePhaseLeaseControllerV2,
    ) -> TProviderResultV2_co: ...
```

The executor builds `ProviderPhaseCallPlanV2` only from the validated canonical
descriptor/mount/readiness snapshot and trusted budget; provider code cannot
construct or select its execution mode. Every boundary phase verifies
execution/action/provider identity, mount/readiness generations, the transport
→ mode matrix and that mount revision/digest, probe version, provider generation/daemon
instance/readiness digest equal the fresh canonical readiness snapshot, and
that the plan deadline equals the trusted budget deadline.
Each boundary method also requires its exact `ProviderCallPhaseV2`; a plan may
not be reused across check/execute/route/verify, and the canonical plan digest
covers the phase and all identity/readiness/deadline fields.
`call_id` is stable across runner, termination, detached and audit records.

Pre-activation cancellation is fail-closed. The runner first evaluates the
trusted token and `time.monotonic() >= absolute_deadline_monotonic`; an already
cancelled call returns `ProviderCallCancelledV2` and an expired call returns
`ProviderCallTimedOutV2` without invoking the closure. Immediately before
`_phase_controller.activate()` and immediately before the provider callable,
the boundary repeats both checks under the same activation lock. Those paths
leave the lease PENDING then revoke it and never expose an ACTIVE capability.

`invoke_execute` receives the executor-created controller paired with
`invocation.phase_lease`, verifies exact view identity and PENDING state,
activates it exactly once, and revokes it in its own `finally` on every return
path. Provider normalization/verify occurs only after revocation, with
executor-internal staging capabilities that are distinct objects and remain
valid. The plan does not claim that Python can forcibly kill an arbitrary
in-process thread.

Exact call-runner contracts:

```python
class ProviderCallTerminationStateV2(str, Enum):
    QUIESCED = "quiesced"
    IPC_CLOSED = "ipc_closed"
    CHILD_COMPLETED = "child_completed"
    DETACHED_FENCED = "detached_fenced"


class ProviderLeaseClosureStateV2(str, Enum):
    NOT_ISSUED = "not_issued"
    REVOKED = "revoked"


@dataclass(frozen=True)
class ProviderCallTerminationReceiptV2:
    call_id: str
    execution_mode: ProviderExecutionModeV2
    state: ProviderCallTerminationStateV2
    quiesced_at_monotonic: float | None
    runner_handle_ref: str | None
    receipt_digest: str


class ProviderCallDetachedV2(RuntimeError):
    call_id: str
    runner_handle_ref: str
    closure_receipt: ProviderBoundaryClosureReceiptV2

    def __init__(
        self,
        *,
        call_id: str,
        runner_handle_ref: str,
        closure_receipt: ProviderBoundaryClosureReceiptV2,
    ) -> None: ...


@dataclass(frozen=True)
class ProviderBoundaryClosureReceiptV2:
    call_receipt: ProviderCallTerminationReceiptV2
    phase: ProviderCallPhaseV2
    lease_state: ProviderLeaseClosureStateV2
    closed_at_monotonic: float
    closure_digest: str


@dataclass(frozen=True)
class DetachedProviderCallRefV2:
    reference: str
    revision: int
    call_id: str
    record_digest: str


@dataclass(frozen=True)
class DetachedProviderCallDraftV2:
    call_id: str
    execution_id: str
    transaction_id: str
    action_id: str
    provider_id: str
    provider_generation: str
    mount_revision: int
    mount_digest: str
    call_plan_digest: str
    runner_handle_ref: str
    closure_receipt: ProviderBoundaryClosureReceiptV2
    provider_call_recovery_ref: ProviderCallRecoveryRefV2
    checkout_recovery_ref: CheckoutRecoveryRefV2 | None
    scope_recovery_ref: InvocationScopeRecoveryRefV2 | None
    coordinator_recovery_ref: ExecutionCommitRecoveryRefV2 | None


class DetachedProviderCallStateV2(str, Enum):
    WAITING_QUIESCENCE = "waiting_quiescence"
    QUIESCED = "quiesced"
    RECONCILING = "reconciling"
    COMPLETED = "completed"


@dataclass(frozen=True)
class DetachedProviderCallRecordV2:
    detached_ref: DetachedProviderCallRefV2
    draft: DetachedProviderCallDraftV2
    state: DetachedProviderCallStateV2
    quiescence_receipt: ProviderCallTerminationReceiptV2 | None
    claim_id: str | None
    claim_expires_at_utc: float | None
    claimer_instance_id: str | None
    claimer_boot_id: str | None
    fencing_token: int
    final_report_ref: str | None
    final_report_revision: int | None
    final_report_digest: str | None


@dataclass(frozen=True)
class ProviderCallCompletedV2(Generic[TProviderResultV2_co]):
    result: TProviderResultV2_co
    termination: ProviderCallTerminationReceiptV2


@dataclass(frozen=True)
class ProviderCallTimedOutV2:
    termination: ProviderCallTerminationReceiptV2


@dataclass(frozen=True)
class ProviderCallCancelledV2:
    termination: ProviderCallTerminationReceiptV2


@dataclass(frozen=True)
class ProviderCallFailedV2:
    redacted_error_code: str
    error_digest: str
    termination: ProviderCallTerminationReceiptV2


@dataclass(frozen=True)
class ProviderCallDetachedOutcomeV2:
    runner_handle_ref: str
    termination: ProviderCallTerminationReceiptV2


ProviderCallRunOutcomeV2: TypeAlias = (
    ProviderCallCompletedV2[TProviderResultV2_co]
    | ProviderCallTimedOutV2
    | ProviderCallCancelledV2
    | ProviderCallFailedV2
    | ProviderCallDetachedOutcomeV2
)


class ProviderCallRunnerV2(Protocol):
    def invoke(
        self,
        call: Callable[[], TProviderResultV2_co],
        *,
        call_plan: ProviderPhaseCallPlanV2,
        cancellation: CancellationToken,
    ) -> ProviderCallRunOutcomeV2[TProviderResultV2_co]: ...


@runtime_checkable
class ProviderCallTerminationStoreV2(Protocol):
    def persist_detached(
        self,
        draft: DetachedProviderCallDraftV2,
    ) -> DetachedProviderCallRecordV2: ...
    def require_detached(
        self,
        reference: DetachedProviderCallRefV2,
    ) -> DetachedProviderCallRecordV2: ...
    def probe_quiescence(
        self,
        reference: DetachedProviderCallRefV2,
        operation: ParticipantOperationContextV2,
        *,
        claim_id: str,
        fencing_token: int,
    ) -> ProviderCallTerminationReceiptV2: ...
    def mark_quiesced(
        self,
        reference: DetachedProviderCallRefV2,
        receipt: ProviderCallTerminationReceiptV2,
        *,
        claim_id: str,
        fencing_token: int,
    ) -> DetachedProviderCallRecordV2: ...
    def claim_reconciliation(
        self,
        reference: DetachedProviderCallRefV2,
        *,
        expected_revision: int,
        claim_id: str,
        claim_expires_at_utc: float,
        claimer_instance_id: str,
        claimer_boot_id: str,
        expected_fencing_token: int,
    ) -> DetachedProviderCallRecordV2: ...
    def renew_claim(
        self,
        reference: DetachedProviderCallRefV2,
        *,
        claim_id: str,
        fencing_token: int,
        new_expires_at_utc: float,
    ) -> DetachedProviderCallRecordV2: ...
    def reclaim_expired(
        self,
        reference: DetachedProviderCallRefV2,
        *,
        expected_revision: int,
        new_claim_id: str,
        new_expires_at_utc: float,
        claimer_instance_id: str,
        claimer_boot_id: str,
        expected_fencing_token: int,
    ) -> DetachedProviderCallRecordV2: ...
    def complete_reconciliation(
        self,
        reference: DetachedProviderCallRefV2,
        *,
        claim_id: str,
        fencing_token: int,
        final_report: ActionExecutionReportEnvelopeV2,
    ) -> DetachedProviderCallRecordV2: ...
    def list_reconcilable(self) -> tuple[DetachedProviderCallRefV2, ...]: ...


@runtime_checkable
class ProviderRunnerRegistryV2(Protocol):
    def probe(
        self,
        runner_handle_ref: str,
        operation: ParticipantOperationContextV2,
    ) -> ProviderCallTerminationReceiptV2: ...


@dataclass(frozen=True)
class ExecutionCommitRecoveryRefV2:
    transaction_id: str
    revision: int
    record_ref: str
    record_digest: str


@runtime_checkable
class ExecutionCommitRecoveryServiceV2(Protocol):
    def require_current_ref(
        self,
        coordinator: ExecutionCommitCoordinator,
    ) -> ExecutionCommitRecoveryRefV2: ...
    def reopen(
        self,
        recovery_ref: ExecutionCommitRecoveryRefV2,
    ) -> ExecutionCommitCoordinator: ...


class DetachedProviderCallOwnerV2:
    """Executor-owned live owner; never serialized or exposed to providers."""

    call_id: str
    runner_handle_ref: str
    phase: ProviderCallPhaseV2
    checkout: ExecutorCheckoutBundle | None
    scope: InvocationScope | None
    coordinator: ExecutionCommitCoordinator | None
    termination_store: ProviderCallTerminationStoreV2
    runner_registry: ProviderRunnerRegistryV2
    checkout_coordinator: ReferenceCheckoutCoordinator | None
    scope_recovery_store: InvocationScopeRecoveryStoreV2 | None
    commit_recovery: ExecutionCommitRecoveryServiceV2 | None

    def reconcile_once(
        self,
        operation: ParticipantOperationContextV2,
    ) -> ExecutionReportViewV2: ...
```

`ExecutionBudget.absolute_deadline_monotonic` is derived from one
`time.monotonic()` clock domain and is never a wall-clock timestamp.
`COOPERATIVE_IN_PROCESS` requests cancellation at deadline and waits a bounded
grace. Every potentially blocking/network/process backend call made by such an
adapter must itself use a deadline-aware IPC call or an executor-owned killable
backend worker with a closed serializable backend request; the full provider
context is never serialized. If the orchestration call still fails to quiesce,
the runner returns `DETACHED_FENCED`; the boundary revokes its phase lease,
requires a non-null stable `runner_handle_ref`, constructs the closure receipt
and raises exact `ProviderCallDetachedV2`. The normal generic return type remains
only `TProviderResultV2_co`. The executor catches that exception,
revalidates `exc.closure_receipt` identity/digest, constructs only the
identity/owner-bearing `DetachedProviderCallDraftV2`, and persists that same
boundary-created closure—it never constructs a second closure receipt. The
store mints/read-backs `DetachedProviderCallRefV2`; the executor CASes that ref
into the provider-call journal's recoverable DETACHED_FENCED record, then retains
checkout/scope/transaction ownership, publishes no success, and durably writes
`DetachedProviderCallRecordV2`; it may clean only after `probe_quiescence()`
returns a matching QUIESCED receipt. If dispatch of an external effect is
possible, the coordinator enters `IN_DOUBT`. While detached,
the report query returns `ExecutionProgressReportV2(TERMINATION_PENDING)` with
no execution result or finalization record; it is not an
`ActionExecutionReportV2` and cannot be used by a router as a child result.
Reconciliation marks the call quiesced, resumes the normal abort/IN_DOUBT
decision, completes cleanup, and only then publishes a final immutable
`ActionExecutionReportV2` revision.
`DEADLINE_LOCAL_IPC` closes the authenticated connection and proves
its reader/writer stopped. `CHILD_EXECUTOR` waits for the child report or fences
the child transaction through the same executor.

Closure evidence is phase-aware. CHECK/VERIFY calls never receive a phase lease
and therefore record `NOT_ISSUED`; EXECUTE/ROUTE record `REVOKED`. Recovery refs
in a detached record are non-null iff that owner had already been created and
checkpointed in the finalization intent. A CHECK detach may therefore have no
checkout/scope/coordinator, while cleanup never assumes those refs exist.

Detached reconciliation uses a store-minted claim lease. Claim/reclaim
increments the fencing token and records durable UTC expiry plus claimer
instance/boot; renew, probe, quiescence transition and completion require the
current claim ID/token. An expired claim may be reclaimed at a higher
token. Probe/runner/reconcile calls always receive bounded
`ParticipantOperationContextV2`; exhaustion leaves the record pending. Final
report ref/revision/digest are non-null iff state=COMPLETED and an identical
replay returns the same record; a conflicting terminal report is rejected.

Boundary exhaustively matches `ProviderCallRunOutcomeV2`: COMPLETED returns the
non-optional result after closure receipt; TIMED_OUT/CANCELLED/FAILED become the
exact bounded executor error/status after revocation; DETACHED requires the
stable runner handle and raises `ProviderCallDetachedV2`. `None` is never a
provider result and every branch carries termination evidence; `assert_never`
ratchets the union.

Mount validation enforces this exact matrix:

| Provider transport | Execution mode | Blocking work rule |
|---|---|---|
| `IN_PROCESS` | `COOPERATIVE_IN_PROCESS` | adapter orchestration only; every blocking backend uses deadline-aware IPC or killable backend worker |
| `LOCAL_DAEMON_IPC` | `DEADLINE_LOCAL_IPC` | socket deadlines + close + termination receipt |
| `CHILD_EXECUTOR` | `CHILD_EXECUTOR` | child budget narrowing and durable child fencing |

All 20 mount rows must match the matrix. A backend with neither cooperative
deadline nor killable worker cannot be mounted. Tests include a deliberately
hung adapter: no scope/checkout cleanup races the running call, all cached
capabilities are revoked, no result is published, and reconciliation begins.

The executor reuses the already intent-attached checkout/coordinator recovery
refs and CAS-checkpoints any new closed scope cleanup descriptors into the
existing scope recovery record. It persists those current refs together with
the exact closure receipt and runner handle;
only a successful durable CAS allows control to detach. A scope containing an
ephemeral/unrecoverable callback is ineligible for detach and remains owned by
the fatal-health emergency registry until quiescence. The in-process
`DetachedProviderCallOwnerV2` retains live checkout/scope/coordinator ownership
and runs the canonical reconciliation/cleanup order. On process restart, a
durable record whose runner handle is absent is treated as OS-terminated only
after the runner registry proves the old process/epoch is dead; checkout and
transaction/scope stores are then reopened from the exact journal refs/digests
and reconciled through their declared recovery services. Raw Python cleanup
callbacks are never reconstructed. If
durable persistence fails while the call remains live, the executor does not
return any report or release resources; it keeps the owner registered in the
process emergency registry and raises a fatal health condition until persistence
or proven quiescence succeeds.

PR-7 adds the separate capability-restricted check and verify methods. Timeout,
cancellation and output limits are always taken from `invocation.budget`.

C2 builders/rebinders receive a read/cleanup-only `C2ArtifactBuildContext`
created from scope/budget/lineage. They never receive staging, participant
registration or the coordinator. They return an unstaged build output; the V2
provider computes the full binding digest and creates the exact PR-6 stage
request before the single staging call.

Implementation ownership:

```text
PR-2 CREATE core/actions/execution_budget.py
    → ExecutionBudget, ExecutionLineage

PR-5 CREATE core/actions/provider_invocation.py
    → PR-5 stage requests/facades
    → BoundProviderInvocationContext

PR-6 MODIFY core/actions/provider_invocation.py
    → C2ArtifactStageRequestV1 method only after its DTO exists

PR-5 CREATE core/actions/provider_call_boundary.py
    → single execute boundary and budget enforcement
```

Required tests include deadline exhaustion, cancellation propagation, output
bounding, child budget narrowing, absence of transaction lifecycle on the
provider context, malicious adapters caching every capability/material and
failing to reuse it after execute, absence of `transfer`/`close` on provider
scope, absence of direct sensitive staging, and a PR-order test proving PR-5
imports no PR-6/PR-7 types.

## 9. Dynamic readiness и request preconditions

## 9.1. Provider readiness and canonical action state

PR-3 owns the readiness support types:

```python
class DependencyKindV2(str, Enum):
    PYTHON_IMPORT = "python_import"
    SYSTEM_BINARY = "system_binary"
    PLATFORM = "platform"
    DAEMON_PROTOCOL = "daemon_protocol"
    PROVIDER_INITIALIZATION = "provider_initialization"


class DependencyStateV2(str, Enum):
    AVAILABLE = "available"
    MISSING = "missing"
    INCOMPATIBLE = "incompatible"
    ERROR = "error"


@dataclass(frozen=True)
class DependencyReadiness:
    dependency_id: str
    kind: DependencyKindV2
    state: DependencyStateV2
    observed_version: str | None
    required_version: str | None
    reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class ProviderReadinessSnapshot:
    action_id: str
    provider_id: str
    mount_revision: int
    mount_digest: str
    probe_version: str
    provider_generation: str
    daemon_instance_id: str | None
    available: bool
    checked_at_monotonic: float
    expires_at_monotonic: float
    dependency_states: tuple[DependencyReadiness, ...]
    reason_codes: tuple[str, ...]
    snapshot_digest: str


def canonical_provider_readiness_digest(
    snapshot: ProviderReadinessSnapshot,
) -> str:
    """Canonical schema-tagged digest excluding snapshot_digest itself."""
    ...


@runtime_checkable
class ProviderReadinessRegistryV2(Protocol):
    def probe(
        self,
        mount: ProviderMountSnapshotV2,
    ) -> ProviderReadinessSnapshot: ...
    def assert_current(
        self,
        snapshot: ProviderReadinessSnapshot,
        mount: ProviderMountSnapshotV2,
    ) -> None: ...
```

Both timestamps use the executor's `time.monotonic()` clock domain. Registry
recheck/read-back recomputes the digest and requires exact field equality before
provider invocation.

PR-2 creates `core/actions/canonical_state.py` and owns the readiness-free
coarse-policy state:

```python
@dataclass(frozen=True)
class CanonicalActionStaticState:
    descriptor: ActionDescriptorV2
    mount: ProviderMountSnapshotV2
```

PR-3 modifies that existing file, and only after
`ProviderReadinessSnapshot` exists adds the full state:

```python
@dataclass(frozen=True)
class CanonicalActionState:
    static: CanonicalActionStaticState
    readiness: ProviderReadinessSnapshot
```

`authorize_coarse(...)` accepts only `CanonicalActionStaticState` and never
probes dependencies. `authorize_deep(...)` receives `CanonicalActionState` after
the authorized initial probe.

Recheck compares:

```text
action_id
provider_id
mount_revision
mount_digest
probe_version
provider_generation
daemon_instance_id
dependency states
expiry
snapshot_digest (recomputed from every preceding field)
```

Mismatch requires a fresh probe or produces `unavailable`. Specific session,
route, credential, agent, channel or target-service existence remains a request
precondition and never becomes provider readiness.

## Kill-chain stage migration

PR-2 должен MODIFY:

core/killchain/policy.py
config.py
config.yaml
tests/test_killchain_policy_coverage.py
tests/test_killchain_config_policy.py

Добавить canonical StageSpec:

credential_access
command_and_control
weaponization

Mapping:

credential_access:
    kerberos_extract_tickets
    kerberos_crack_tickets
    ad_dump_lsass
    ad_sam_dump

lateral_movement:
    ad_pass_the_ticket
    pass_the_hash
    ad_smbexec
    ad_winrm_exec
    ad_dcom_exec
    ad_remote_execution
    pivot_remote_forward
    pivot_ssh_chain
    pivot_proxy_scan

command_and_control:
    dns_c2_channel
    c2_enroll
    c2_deploy
    c2_channel_create
    c2_task
    c2_cleanup

weaponization:
    payload_keying

New stages default deny until explicitly present in migrated configuration.
Reference-runtime fixture enables them explicitly. Unknown stages remain denied.

### 9.2. Recheck contract

Readiness проверяется только после successful coarse authorization:

```text
первый раз после authorize_coarse и до typed/fact/reference detail disclosure through deep policy
повторно после atomic snapshot/reference checkout and PENDING reservation, но до `open_materials()`
непосредственно перед material open and provider attempt start
```

Initial probe не выполняется до coarse policy и не раскрывает provider/dependency details неавторизованному caller.

Recheck сверяет:

```text
action_id
provider_id
mount_revision
mount_digest
probe_version
provider_generation
daemon instance ID, если применимо
dependency state
expiry
snapshot_digest, recomputed from the canonical snapshot body
```

Несовпадение fenced поля требует нового probe либо возвращает unavailable.

---

## 10. Closed typed inputs и согласованная C2 enrollment lifecycle

Открытые словари запрещены:

```text
channel_options: dict
deployment_profile: dict
arguments: dict
provider parameters: dict
arbitrary command
arbitrary output path
```

### 10.0. Canonical supporting enums и enrollment input

Single-owner rules:

```text
TargetRole, TargetKind, NetworkProtocol
    owner: core/actions/target_scope.py (PR-4)

RemoteExecService
    owner: core/actions/operation_catalog.py (PR-6)

C2DeploymentProfileId, C2DeploymentMethod, C2TargetOS, C2TargetArch
    owner: core/c2/deployment_profiles.py (PR-6)

DNSRecordType, DNSChannelConfig, C2Transport, C2TransportConfig
    owner: core/c2/transport_catalog.py (PR-6)

C2CleanupReason
    owner: core/c2/resource_types.py (PR-6)
```

```python
class RemoteExecService(str, Enum):
    SMB = "smb"
    WINRM = "winrm"
    DCOM = "dcom"


class C2DeploymentProfileId(str, Enum):
    GO_AGENT = "deployment://go-agent"
    PYTHON_AGENT = "deployment://python-agent"
    POWERSHELL_STAGER = "deployment://powershell-stager"


class C2DeploymentMethod(str, Enum):
    SSH_SESSION = "ssh-session"


class C2TargetOS(str, Enum):
    LINUX = "linux"
    WINDOWS = "windows"
    DARWIN = "darwin"


class C2TargetArch(str, Enum):
    AMD64 = "amd64"
    ARM64 = "arm64"


class DNSRecordType(str, Enum):
    TXT = "TXT"
    A = "A"


class C2Transport(str, Enum):
    DNS = "dns"


class C2CleanupReason(str, Enum):
    OPERATOR_REQUEST = "operator-request"
    MISSION_TEARDOWN = "mission-teardown"
    EXPIRED = "expired"
    RECONCILIATION = "reconciliation"
```

`C2EnrollmentIssueInput` is owned by `core/actions/input_contracts.py`; supporting
profile/protocol enums are imported from their canonical modules:

```python
@dataclass(frozen=True)
class C2EnrollmentIssueInput:
    channel_ref: str
    target: str
    profile_id: C2DeploymentProfileId
    agent_protocol_version: Literal["12.0"]
    ttl_seconds: int
    max_uses: Literal[1] = 1
```

Canonical enrollment bounds are owned by `core/runtime_config.py` and exposed by
exact config/environment keys:

```text
config.yaml:
  c2:
    enrollment:
      ttl_min_seconds: 60
      ttl_default_seconds: 900
      ttl_max_seconds: 3600
      max_uses_default: 1
      max_uses_max: 1

.env / environment overrides:
  OCTOPUS_C2_ENROLLMENT_TTL_MIN_SECONDS
  OCTOPUS_C2_ENROLLMENT_TTL_DEFAULT_SECONDS
  OCTOPUS_C2_ENROLLMENT_TTL_MAX_SECONDS
  OCTOPUS_C2_ENROLLMENT_MAX_USES_DEFAULT
  OCTOPUS_C2_ENROLLMENT_MAX_USES_MAX
```

Startup validation is fail closed:

```text
1 <= ttl_min_seconds <= ttl_default_seconds <= ttl_max_seconds
max_uses_default == max_uses_max == 1
all values are bounded integers
invalid or contradictory values stop C2/provider readiness
```

Decoder bounds:

```text
ttl_seconds: ttl_min_seconds..ttl_max_seconds
max_uses: exactly 1
agent_protocol_version: exactly supported closed value
mission/owner/principal: never caller fields; resolved by executor
```

No supporting enum may be redefined in `input_contracts.py`, adapters or provider
modules. Architecture tests enforce one class owner and exact values for every
enum and runtime-bound key above.

### 10.1. Remote execution

```python
class RemoteExecOperationId(str, Enum):
    IDENTITY = "operation://identity"
    HOST_INVENTORY = "operation://host-inventory"
    NETWORK_INVENTORY = "operation://network-inventory"
    SERVICE_INVENTORY = "operation://service-inventory"
```

```python
@dataclass(frozen=True)
class RemoteExecInputV2:
    credential_ref: str
    target: str
    operation_id: RemoteExecOperationId
    service: RemoteExecService | None = None
```

### 10.2. Pivot

```python
@dataclass(frozen=True)
class RemoteForwardInputV2:
    session_ref: str
    target: str
    remote_port: int
    destination_host: str
    destination_port: int
```

```python
@dataclass(frozen=True)
class SSHChainHopInputV2:
    target: str
    credential_ref: str
    port: int = 22
```

```python
@dataclass(frozen=True)
class SSHChainInputV2:
    hops: tuple[SSHChainHopInputV2, ...]
```

```python
@dataclass(frozen=True)
class PivotProxyScanInputV2:
    route_ref: str
    target: str
    ports: tuple[int, ...]
    timeout_seconds: int
```

### 10.3. Kerberos

```python
@dataclass(frozen=True)
class KerberosExtractInputV2:
    credential_ref: str
    target: str
```

```python
class KerberosHashMode(str, Enum):
    KERBEROAST = "kerberoast"
    ASREP = "asrep"
```

```python
@dataclass(frozen=True)
class KerberosCrackInputV2:
    ticket_ref: str
    mode: KerberosHashMode
    wordlist_ref: str
```

### 10.4. AD credential providers

```python
@dataclass(frozen=True)
class PassTheTicketInputV2:
    ticket_ref: str
    target: str
    operation_id: RemoteExecOperationId
```

```python
@dataclass(frozen=True)
class PassTheHashInputV2:
    credential_ref: str
    target: str
    operation_id: RemoteExecOperationId
```

```python
@dataclass(frozen=True)
class CredentialDumpInputV2:
    credential_ref: str
    target: str
```

### 10.5. Payload keying

```python
class PayloadKeyingProfileId(str, Enum):
    HOSTNAME = "keying://hostname"
    USER = "keying://user"
    MAC = "keying://mac"
    MACHINE_ID = "keying://machine-id"
    MULTI = "keying://multi"
```

```python
@dataclass(frozen=True)
class PayloadKeyingInputV2:
    payload_ref: str
    profile_id: PayloadKeyingProfileId
    target_metadata_ref: str | None
```

### 10.6. C2 agent task protocol migration

Typed `c2_task` несовместим с текущим agent wire, использующим поле `command`.
Ввести:

```python
# Owner: core/c2/agent_task_protocol.py, created in PR-6.
class AgentPayloadSchemaIdV12(str, Enum):
    IDENTITY_V1 = "c2-agent-payload/identity/1"
    HOST_INVENTORY_V1 = "c2-agent-payload/host-inventory/1"
    NETWORK_INVENTORY_V1 = "c2-agent-payload/network-inventory/1"
    SERVICE_INVENTORY_V1 = "c2-agent-payload/service-inventory/1"


# Owner: core/c2/agent_task_protocol.py, created in PR-6.
class AgentResultSchemaIdV12(str, Enum):
    IDENTITY_V1 = "c2-agent-result/identity/1"
    HOST_INVENTORY_V1 = "c2-agent-result/host-inventory/1"
    NETWORK_INVENTORY_V1 = "c2-agent-result/network-inventory/1"
    SERVICE_INVENTORY_V1 = "c2-agent-result/service-inventory/1"
```

The only protocol constants are owned by PR-6
`core/c2/agent_task_protocol.py`:

```python
C2_AGENT_PROTOCOL_V11: Final = "11.0"
C2_AGENT_PROTOCOL_V12: Final = "12.0"
C2_TASK_SCHEMA_V12: Final = "12.0"
```

PR-15 imports these names and does not declare `VERSION`,
`C2_AGENT_PROTOCOL_VERSION` or `LEGACY_V11` aliases.

Registration payload V12:

```python
@dataclass(frozen=True)
class AgentCapabilitySetV12:
    supported_operation_ids: tuple[C2TaskOperationId, ...]
    supported_payload_schema_versions: tuple[AgentPayloadSchemaIdV12, ...]
    supported_result_schema_versions: tuple[AgentResultSchemaIdV12, ...]
    capabilities_digest: str


@dataclass(frozen=True)
class AgentRegistrationV12:
    protocol_version: Literal["12.0"]
    capabilities: AgentCapabilitySetV12
    deployment_ref: str
    artifact_binding_digest: str
    enrollment_token: SecretValue
    hostname: str
    os: C2TargetOS
    arch: C2TargetArch
    user: str
```

`AgentRegistrationV12` is a host-side typed model, not a generic JSON DTO.
PR-15 owns one `AgentWireCodecV12` for registration, task, result and delivery
ACK. Its registration path acquires one single-use lease from
`enrollment_token`, writes only into a zeroizable destination and clears both
leases in `finally`; bounded decode writes token bytes directly into
`OpaqueSecretValueV2`. Generic dataclass/JSON serialization of `SecretValue` is
forbidden. Python/Go codec vectors include every message kind, length limits,
redaction and zeroization assertions.

`capabilities_digest` is SHA-256 over canonical JSON containing the sorted exact
operation IDs, payload schema versions and result schema versions. Daemon
recomputes it before persistence; a caller-supplied digest is never trusted.

Канонические `AgentTaskEnvelopeV12`, `AgentTaskResultV12` и
`AgentTaskDeliveryAckV12` определяются ровно один раз в PR-15 §15.2–§15.3.
Operator result acknowledgement не является agent-wire DTO; его единственный
owner — `ResultAckRequestV1` из PR-14 §14.7. Этот раздел не содержит
параллельных task/result/ACK моделей.

Go/Python agents implement a closed handler registry:

```text
IDENTITY
HOST_INVENTORY
NETWORK_INVENTORY
SERVICE_INVENTORY
```

V12 agent code must not execute `task["command"]` or invoke arbitrary
shell/process arguments from wire payload.

Migration sequence:

```text
1. daemon accepts V11 and V12 registration during transition;
2. agents table stores protocol version, operation/payload/result capabilities and artifact binding digest;
3. V12 builder/implants ship typed handler registry;
4. c2_task request precondition requires protocol >=12 and operation/payload/result capability;
5. no new V11 raw tasks after cutover flag;
6. existing pending V11 tasks are drained/cancelled explicitly;
7. V11 agents remain visible but fail typed-task request preconditions;
8. legacy raw task control action is disabled by default and never exposed through typed provider/CLI;
9. remove V11 raw task emission after migration window.
```

DB schema details and the only normative V12 task/result DTO versions live in
PR-15.

### 10.7. Exact C2 enrollment lifecycle and bootstrap capability

Canonical enrollment models are created in PR-15 because the PR-15 builder and
implant migration consume them. PR-16 modifies them but does not create them.

```python
class EnrollmentLifecycleState(str, Enum):
    ISSUED = "issued"
    RESERVED_FOR_BUILD = "reserved_for_build"
    EMBEDDED_IN_ARTIFACT = "embedded_in_artifact"
    RESERVED_FOR_DEPLOYMENT = "reserved_for_deployment"
    CONSUMED_BY_AGENT = "consumed_by_agent"
    REVOKED = "revoked"
    EXPIRED = "expired"


class EnrollmentBootstrapState(str, Enum):
    AVAILABLE = "available"
    LEASED = "leased"
    CONSUMED = "consumed"
    CLEARED = "cleared"


class EnrollmentBuildCheckoutState(str, Enum):
    OPEN = "open"
    MATERIAL_EXPOSED = "material_exposed"
    TRANSFERRED = "transferred"
    CLOSED = "closed"


@runtime_checkable
class EnrollmentBootstrapMaterial(Protocol):
    @property
    def material_id(self) -> str: ...
    @property
    def reservation_id(self) -> str: ...
    @property
    def transaction_id(self) -> str: ...
    @property
    def byte_length(self) -> int: ...
    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...
    @property
    def state(self) -> EnrollmentBootstrapState: ...

    def acquire_for_build(
        self,
        *,
        expected_reservation_id: str,
        expected_transaction_id: str,
        consumer_id: str,
    ) -> ZeroizableSensitiveBufferLeaseV2: ...

    def clear(self) -> None: ...


@runtime_checkable
class EnrollmentBuildMaterialViewV1(Protocol):
    """Provider/builder view; no release, transfer, close or C2 client surface."""

    @property
    def enrollment_ref(self) -> str: ...
    @property
    def reservation_id(self) -> str: ...
    @property
    def transaction_id(self) -> str: ...
    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2: ...
    def acquire_bootstrap_for_build(
        self,
        *,
        consumer_id: str,
    ) -> ZeroizableSensitiveBufferLeaseV2: ...


class EnrollmentBuildCheckout:
    """Daemon-backed, transaction-bound reservation with monotonic state."""

    enrollment_ref: str
    checkout_id: str
    enrollment_revision: int
    reservation_id: str
    transaction_id: str
    phase_lease: ProviderExecutePhaseLeaseV2
    channel_ref: str
    target: str
    profile_id: C2DeploymentProfileId
    agent_protocol_version: Literal["12.0"]
    bootstrap_material: EnrollmentBootstrapMaterial
    state: EnrollmentBuildCheckoutState

    def provider_view(self) -> EnrollmentBuildMaterialViewV1: ...
    def _mark_material_exposed(self) -> None: ...
    def transfer_to_participant(
        self,
        registration_ref: ParticipantRegistrationRefV2,
    ) -> None: ...
    def close_checkout(self) -> None: ...
```

Reservation ownership is exact:

```text
close OPEN before exposure:
    CAS RESERVED_FOR_BUILD → ISSUED and release the reservation;
close MATERIAL_EXPOSED before transfer:
    revoke enrollment and destroy bootstrap material;
TRANSFERRED:
    enrollment participant owns rollback/reconcile; checkout close is no-op;
outer finally:
    always invokes close_checkout();
startup:
    QUERY_ENROLLMENT_BUILD_RESERVATION finds transaction-bound orphan records
    and releases or revokes them according to exposure state.
```

`provider_view()` is the only object placed in `BoundEnrollmentMaterial`.
`acquire_bootstrap_for_build()` first requires the active execute-phase lease and
invokes the private checkout's `_mark_material_exposed()`. The daemon durably
CASes OPEN→MATERIAL_EXPOSED and acknowledges that state before any bootstrap
byte is streamed into the zeroizable destination. Failure after that CAS causes
outer checkout close to revoke the enrollment. The view has
no close/transfer method. After provider return, the executor validates the
enrollment participant registration and calls the private
`transfer_to_participant()` before verify; on any mismatch/failure outer finally
closes the checkout.

PR-14 control protocol includes exact signed
`RELEASE_ENROLLMENT_BUILD_RESERVATION` and
`QUERY_ENROLLMENT_BUILD_RESERVATION` commands; PR-15 owns their typed enrollment
payload codecs. `bootstrap_material.clear()` alone is not reservation cleanup.

PR-15 creates `core/c2/enrollment_control_models.py` and
`core/c2/enrollment_control_codec.py` with the sole pre-participant wire model:

```python
@dataclass(frozen=True)
class EnrollmentBuildReservationRequestV1:
    schema_version: Literal["1.0"]
    authorization: ExecutionControlAuthorizationV1
    enrollment_ref: str
    expected_enrollment_revision: int
    target: str
    channel_ref: str
    profile_id: C2DeploymentProfileId
    expected_agent_protocol: Literal["12.0"]
    expires_at: float


@dataclass(frozen=True)
class EnrollmentBuildReservationReceiptV1:
    schema_version: Literal["1.0"]
    transaction_id: str
    request_id: str
    enrollment_ref: str
    enrollment_revision: int
    reservation_id: str
    reservation_revision: int
    state: Literal[EnrollmentBuildCheckoutState.OPEN]
    expires_at: float
    receipt_digest: str


@dataclass(frozen=True)
class EnrollmentBuildMaterialCheckoutRequestV1:
    schema_version: Literal["1.0"]
    authorization: ExecutionControlAuthorizationV1
    enrollment_ref: str
    reservation_id: str
    expected_reservation_revision: int
    destination_capacity: int


@dataclass(frozen=True)
class EnrollmentBuildMaterialCheckoutReceiptV1:
    schema_version: Literal["1.0"]
    transaction_id: str
    enrollment_ref: str
    reservation_id: str
    reservation_revision: int
    state: Literal[EnrollmentBuildCheckoutState.MATERIAL_EXPOSED]
    material_id: str
    material_byte_length: int
    integrity_tag: SensitiveIntegrityTagV2
    receipt_digest: str


@dataclass(frozen=True)
class EnrollmentBuildReservationReleaseRequestV1:
    schema_version: Literal["1.0"]
    authorization: ExecutionControlAuthorizationV1
    enrollment_ref: str
    reservation_id: str
    expected_reservation_revision: int
    exposure_observed: bool


@dataclass(frozen=True)
class EnrollmentBuildReservationQueryV1:
    schema_version: Literal["1.0"]
    authorization: ExecutionControlAuthorizationV1
    enrollment_ref: str
    reservation_id: str


@dataclass(frozen=True)
class EnrollmentBuildReservationSnapshotV1:
    schema_version: Literal["1.0"]
    transaction_id: str
    request_id: str
    enrollment_ref: str
    enrollment_revision: int
    reservation_id: str
    reservation_revision: int
    state: EnrollmentBuildCheckoutState
    material_exposed: bool
    transferred_participant_id: str | None
    expires_at: float
    snapshot_digest: str


@dataclass(frozen=True)
class EnrollmentBuildReservationReleaseReceiptV1:
    schema_version: Literal["1.0"]
    transaction_id: str
    enrollment_ref: str
    reservation_id: str
    reservation_revision: int
    final_enrollment_state: EnrollmentLifecycleState
    receipt_digest: str


EnrollmentBuildControlRequestV1: TypeAlias = (
    EnrollmentBuildReservationRequestV1
    | EnrollmentBuildMaterialCheckoutRequestV1
    | EnrollmentBuildReservationReleaseRequestV1
    | EnrollmentBuildReservationQueryV1
)

EnrollmentBuildControlResponseV1: TypeAlias = (
    EnrollmentBuildReservationReceiptV1
    | EnrollmentBuildReservationReleaseReceiptV1
    | EnrollmentBuildReservationSnapshotV1
    | BoundedControlErrorV1
)


class EnrollmentBuildControlCodecV1(Protocol):
    def encode_request(self, request: EnrollmentBuildControlRequestV1) -> bytes: ...
    def decode_nonsecret_response(
        self,
        frame: bytes,
    ) -> EnrollmentBuildControlResponseV1: ...
    def checkout_material_into(
        self,
        frame_reader: BoundedFrameReaderV1,
        destination: ZeroizableDestinationBufferV2,
        *,
        expected_request: EnrollmentBuildMaterialCheckoutRequestV1,
    ) -> EnrollmentBuildMaterialCheckoutReceiptV1: ...
```

`EnrollmentBuildControlRequestV1` and `EnrollmentBuildControlResponseV1` are
closed tagged unions of the DTO above plus the exact bounded control error.
Request IDs/enrollment/reservation IDs are at most 256 UTF-8 bytes; material is
1..65,536 bytes; checkout expiry is at most 300 seconds and cannot exceed the
approval/transaction deadline. The codec validates exact fields, duplicate
keys, request/transaction/action/digest/revision binding and length before any
allocation. The secret-bearing CHECKOUT response is a framed metadata header
followed by one bounded binary segment streamed directly into the owned
zeroizable destination—never generic JSON, `bytes`, `str` or a response DTO.
The daemon durably commits `MATERIAL_EXPOSED` before sending the first secret
byte. A short/extra/keyed-integrity-mismatched stream zeroizes the destination and leaves
the reservation exposed so outer-close revokes it.

These four commands use only `ExecutionControlAuthorizationV1`; their durable
reservation records are keyed by `(transaction_id, request_id, enrollment_ref)`.
Reserve precedes approval-attempt START. A crash before START is recovered by
query then release/revoke; after START no approval use is refunded.

The revisioned lifecycle is:

```text
ISSUED
→ RESERVED_FOR_BUILD
→ EMBEDDED_IN_ARTIFACT
→ RESERVED_FOR_DEPLOYMENT
→ CONSUMED_BY_AGENT
```

`REVOKED` and `EXPIRED` are terminal. Current builder self-issuance and arbitrary
plaintext enrollment-token inputs are removed.

### 10.7A. Exact deploy/source/build/rebind/stage models

Owners:

```text
core/actions/input_contracts.py   → C2DeployInputV3
core/c2/build_models.py           → source/binding/build-output/stage DTO
core/c2/rebind_models.py          → RebindManifestV1
core/c2/artifact_builder.py       → builder implementation
core/c2/artifact_rebinder.py      → rebinder implementation
ProviderStagingFacade             → only artifact staging point
```

Exact deployment source and input:

```python
@dataclass(frozen=True)
class PrebuiltArtifactSource:
    artifact_ref: str
    rebind_manifest_ref: str


@dataclass(frozen=True)
class BuildTemplateSource:
    template_ref: str
    target_os: C2TargetOS
    target_arch: C2TargetArch


C2DeploymentSource: TypeAlias = PrebuiltArtifactSource | BuildTemplateSource


@dataclass(frozen=True)
class C2DeployInputV3:
    target: str
    source: C2DeploymentSource
    channel_ref: str
    enrollment_ref: str
    access_session_ref: str
    profile_id: C2DeploymentProfileId
    method: C2DeploymentMethod


@dataclass(frozen=True)
class BoundDeploymentReservationV1:
    """Executor-issued logical identity; it is not a live resource capability."""

    transaction_id: str
    request_id: str
    deployment_ref: str
    mission_id: str
    subject_id: str
    action_id: Literal["c2:c2_deploy"]
    target: str
    method: C2DeploymentMethod
    request_digest: str
    idempotency_digest: str
    reservation_digest: str
```

Before provider invocation the executor idempotently preallocates this
reservation from canonical request/mission/subject/transaction identity and
places it only in `BoundEnrollmentMaterial`. It exposes no store or mutation
method. `C2ArtifactBuildBinding.deployment_ref` must equal the reservation ref.
The deployment `ExternalEffectParticipantRegistrationPayloadV2` uses a
`DeferredManagedResourceRequestV2(preallocated_reference=deployment_ref, ...)`;
the coordinator verifies every binding field and returns a draft carrying that
same ref. It never allocates a second deployment identity.

Rebind and build models:

```python
class C2ArtifactIntegrityMismatch(RuntimeError):
    pass


class RebindEncodingV1(str, Enum):
    CANONICAL_JSON_AES_GCM = "canonical_json_aes_gcm"


@dataclass(frozen=True)
class RebindManifestV1:
    schema_version: Literal["1.0"]
    source_artifact_ref: str
    source_sealed_record_digest: str
    source_integrity_tag: SensitiveIntegrityTagV2
    source_provenance_digest: str
    target_os: C2TargetOS
    target_arch: C2TargetArch
    profile_id: C2DeploymentProfileId
    config_slot_offset: int
    config_slot_capacity: int
    encoding: RebindEncodingV1
    immutable_prefix_digest: str
    immutable_suffix_digest: str
    reviewer_subject_id: str
    review_revision: int
    manifest_digest: str


@dataclass(frozen=True)
class C2ArtifactBuildBinding:
    schema_version: Literal["1.0"]
    deployment_ref: str
    enrollment_ref: str
    channel_ref: str
    target: str
    target_os: C2TargetOS
    target_arch: C2TargetArch
    profile_id: C2DeploymentProfileId
    method: C2DeploymentMethod
    agent_protocol_version: Literal["12.0"]
    mission_id: str
    owner_subject_id: str
    source_binding_digest: str


@dataclass(frozen=True)
class C2ArtifactBuildRequest:
    source: BuildTemplateSource
    binding: C2ArtifactBuildBinding


@dataclass(frozen=True)
class C2ArtifactRebindingRequest:
    source_artifact_ref: str
    rebind_manifest_ref: str
    binding: C2ArtifactBuildBinding


class _C2ArtifactBuildOutputConstructionTokenV1:
    pass


@runtime_checkable
class C2SensitiveArtifactBuildSinkV1(Protocol):
    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2: ...
    def write_chunk(self, source: memoryview) -> None: ...
    def finalize(
        self,
        *,
        artifact_kind: Literal[ArtifactKind.C2_AGENT],
        media_type: str,
        source_binding_digest: str,
        metadata_digest: str,
    ) -> C2ArtifactBuildOutput: ...
    def abort_and_destroy(self) -> None: ...


@dataclass(frozen=True, repr=False)
class C2ArtifactBuildContext:
    scope: ProviderInvocationScopeV2 = field(repr=False, compare=False)
    artifact_sink: C2SensitiveArtifactBuildSinkV1 = field(
        repr=False,
        compare=False,
    )
    budget: ExecutionBudget
    lineage: ExecutionLineage


@dataclass(frozen=True, repr=False, init=False)
class C2ArtifactBuildOutput:
    transient_ref: PhaseBoundTransientRefV2 = field(repr=False, compare=False)
    artifact_kind: Literal[ArtifactKind.C2_AGENT]
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    size: int
    media_type: str
    source_binding_digest: str
    metadata_digest: str

    @classmethod
    def _from_sink(
        cls,
        *,
        transient_ref: PhaseBoundTransientRefV2,
        artifact_kind: Literal[ArtifactKind.C2_AGENT],
        sealed_record_digest: str,
        integrity_tag: SensitiveIntegrityTagV2,
        size: int,
        media_type: str,
        source_binding_digest: str,
        metadata_digest: str,
        _token: _C2ArtifactBuildOutputConstructionTokenV1,
    ) -> C2ArtifactBuildOutput: ...


@dataclass(frozen=True)
class C2ArtifactStageRequestV1:
    transient_id: str
    artifact_kind: Literal[ArtifactKind.C2_AGENT]
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    size: int
    media_type: str
    source: C2DeploymentSource
    binding: C2ArtifactBuildBinding
    artifact_binding_digest: str
    metadata_digest: str


@dataclass(frozen=True)
class C2ArtifactStageReceiptV1:
    transaction_id: str
    artifact_draft_ref: SensitiveArtifactDraftRefV2
    artifact_participant_registration_ref: ParticipantRegistrationRefV2
    deployment_ref: str
    enrollment_ref: str
    channel_ref: str
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    artifact_binding_digest: str


@dataclass(frozen=True)
class StagedC2Artifact:
    transaction_id: str
    artifact_draft_ref: SensitiveArtifactDraftRefV2
    artifact_participant_registration_ref: ParticipantRegistrationRefV2
    deployment_ref: str
    enrollment_ref: str
    channel_ref: str
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    artifact_binding_digest: str
```

`C2_AGENT` is always a sensitive artifact because its constructed image embeds
single-use enrollment bootstrap material.  PR-15 creates the concrete
executor-owned `C2SensitiveArtifactBuildSinkV1`.  The sink is bound to the
current transaction, phase lease, `OwnedHmacSensitiveIntegrityAuthenticatorV2`
and `SensitiveArtifactEnvelopeWriterV2`.  Its only provider-visible operations
accept bounded borrowed `memoryview` chunks and `finalize()`; finalization wipes
every plaintext work buffer, seals the image, consumes the writer reservation
through the mutually exclusive
`transfer_sealed_to_backend_transient()` path, registers that store-issued
backend receipt through the current `ProviderInvocationScopeV2`, and returns the
resulting phase-bound
`C2ArtifactBuildOutput`.  A builder cannot construct that output directly,
select an authenticator, export a key, or return plaintext bytes.  Abort or
exception destroys the envelope wrapping key and closes the transient.

The returned `sealed_record_digest` hashes only the ciphertext envelope.  The
opaque `integrity_tag` authenticates the plaintext under the domain
`octopus/c2-agent-artifact/v1`; it is never a report/audit field and is verified
only by the executor/store keyring.  No unkeyed digest of the secret-bearing
agent image is computed or persisted.

Builder/rebinder signatures:

The following Protocols are created only in PR-15 after
`EnrollmentBuildCheckout` exists. PR-6 owns the request/output/stage DTO above
but does not annotate or import the future checkout type.

```python
class C2ArtifactBuilder(Protocol):
    def build(
        self,
        request: C2ArtifactBuildRequest,
        enrollment_material: EnrollmentBuildMaterialViewV1,
        context: C2ArtifactBuildContext,
    ) -> C2ArtifactBuildOutput: ...


class C2ArtifactRebinder(Protocol):
    def rebind(
        self,
        request: C2ArtifactRebindingRequest,
        enrollment_material: EnrollmentBuildMaterialViewV1,
        context: C2ArtifactBuildContext,
    ) -> C2ArtifactBuildOutput: ...
```

The single binding formula is computed before staging:

```text
artifact_binding_digest = SHA-256(canonical JSON {
    schema_version: "c2-artifact-binding-v1",
    sealed_record_digest,
    integrity_tag: {
        key_id,
        algorithm,
        domain,
        tag
    },
    deployment_ref,
    enrollment_ref,
    channel_ref,
    target,
    profile_id,
    method,
    agent_protocol_version,
    mission_id,
    owner_subject_id,
    source_binding_digest,
    target_os,
    target_arch
})
```

The provider must perform exactly this order:

```python
build_output = builder.build(...) or rebinder.rebind(...)

build_output.transient_ref.require_active()
if (
    build_output.transient_ref.phase_lease is not invocation.phase_lease
    or context.scope.phase_lease is not invocation.phase_lease
    or enrollment_material.phase_lease is not invocation.phase_lease
):
    raise C2ArtifactIntegrityMismatch("phase_lease_identity")

if build_output.source_binding_digest != build_binding.source_binding_digest:
    raise C2ArtifactIntegrityMismatch("source_binding_digest")

artifact_binding_digest = artifact_binding_hasher.digest(
    binding=build_binding,
    sealed_record_digest=build_output.sealed_record_digest,
    integrity_tag=build_output.integrity_tag,
)

stage_request = C2ArtifactStageRequestV1(
    transient_id=build_output.transient_ref.transient_id,
    artifact_kind=build_output.artifact_kind,
    sealed_record_digest=build_output.sealed_record_digest,
    integrity_tag=build_output.integrity_tag,
    size=build_output.size,
    media_type=build_output.media_type,
    source=request.source,
    binding=build_binding,
    artifact_binding_digest=artifact_binding_digest,
    metadata_digest=build_output.metadata_digest,
)

artifact_stage = invocation.staging.stage_c2_artifact(stage_request)

staged_artifact = StagedC2Artifact(
    transaction_id=artifact_stage.transaction_id,
    artifact_draft_ref=artifact_stage.artifact_draft_ref,
    artifact_participant_registration_ref=artifact_stage.artifact_participant_registration_ref,
    deployment_ref=artifact_stage.deployment_ref,
    enrollment_ref=artifact_stage.enrollment_ref,
    channel_ref=artifact_stage.channel_ref,
    sealed_record_digest=artifact_stage.sealed_record_digest,
    integrity_tag=artifact_stage.integrity_tag,
    artifact_binding_digest=artifact_stage.artifact_binding_digest,
)
```

`ProviderStagingFacade.stage_c2_artifact(...)` performs one atomic transfer,
integrity validation and internal artifact-participant registration; its receipt
always contains the exact `artifact_participant_registration_ref`. Provider code
cannot register a broad local-store participant. Staging never invents binding
fields, and builder/rebinder never returns a staged object.

Before transfer the facade resolves `stage_request.source` through executor-only
template/artifact/manifest stores, claims the current-scope
`ReadableArtifactTransientV2`, validates its store-issued seal receipt, streams
the ciphertext envelope through the non-sensitive digest sink, and verifies the
plaintext keyed tag through the injected authenticator without exposing either
plaintext or key material. It recomputes actual envelope size/ciphertext digest
and canonical metadata digest. It then
derives `source_binding_digest` itself from the resolved immutable source
snapshot (template digest or artifact+manifest content/provenance/review
revisions) plus transient provenance and requires equality with
`binding.source_binding_digest`; provider/build-output claims are never inputs
to this decision. It checks binding target/OS/arch/profile/method against the
resolved source and request. For prebuilt sources it verifies manifest
digest/revision/reviewer authorization, source content/provenance, immutable
prefix/suffix and slot bounds before accepting the mutated transient. Any
mismatch deletes/zeroizes the transient and produces no draft or participant.

The persisted artifact metadata contains exact target OS/arch and binding
digest. `AgentRegistrationV12` acceptance requires registration OS/arch,
deployment ref and artifact binding digest to equal that stored metadata before
an agent row becomes active.

The digest input excludes the digest itself, artifact ref, local path, plaintext
bootstrap material and transaction-local handles.

`MARK_ENROLLMENT_EMBEDDED` is no longer called by the provider. After artifact
staging the provider stages an exact enrollment-deployment plan payload and
registers a durable `CrossProcessControlParticipantRegistrationPayloadV2` enrollment participant. The coordinator-owned
participant `prepare()` atomically performs the embedded transition and the
deployment reservation, eliminating the gap between a direct mark and
participant registration.

### 10.8. Production builder ownership

Within the current 20 identities the only production caller is `c2_deploy`.
CLI/runner/post-tools build commands return `typed_action_required:c2_deploy` or
are removed from production UI. A standalone production builder would require a
21st canonical action and is not hidden as a helper path.

### 10.9. C2 task typed DTO

```python
class C2TaskOperationId(str, Enum):
    IDENTITY = "c2-operation://identity"
    HOST_INVENTORY = "c2-operation://host-inventory"
    NETWORK_INVENTORY = "c2-operation://network-inventory"
    SERVICE_INVENTORY = "c2-operation://service-inventory"
```

Canonical owner: `core/c2/task_catalog.py` in PR-6. No second enum is allowed.

Closed control-plane payload DTOs:

```python
@dataclass(frozen=True)
class IdentityTaskPayload:
    payload_kind: Literal["identity"] = field(default="identity", init=False)
    schema_version: Literal["c2-control-payload/identity/1"] = field(
        default="c2-control-payload/identity/1", init=False
    )


@dataclass(frozen=True)
class HostInventoryTaskPayload:
    include_processes: bool
    include_services: bool
    max_items: int
    payload_kind: Literal["host_inventory"] = field(default="host_inventory", init=False)
    schema_version: Literal["c2-control-payload/host-inventory/1"] = field(
        default="c2-control-payload/host-inventory/1", init=False
    )


@dataclass(frozen=True)
class NetworkInventoryTaskPayload:
    include_routes: bool
    include_connections: bool
    max_items: int
    payload_kind: Literal["network_inventory"] = field(default="network_inventory", init=False)
    schema_version: Literal["c2-control-payload/network-inventory/1"] = field(
        default="c2-control-payload/network-inventory/1", init=False
    )


@dataclass(frozen=True)
class ServiceInventoryTaskPayload:
    service_names: tuple[str, ...]
    include_status: bool
    payload_kind: Literal["service_inventory"] = field(default="service_inventory", init=False)
    schema_version: Literal["c2-control-payload/service-inventory/1"] = field(
        default="c2-control-payload/service-inventory/1", init=False
    )


C2TaskPayload = (
    IdentityTaskPayload | HostInventoryTaskPayload | NetworkInventoryTaskPayload | ServiceInventoryTaskPayload
)
```

Decoder bounds:

```text
max_items: 1..1024
service_names: 1..128 unique normalized service names
all variants reject unknown fields
operation_id must match the payload variant
```

```python
@dataclass(frozen=True)
class C2TaskInputV2:
    agent_ref: str
    target: str | None
    operation_id: C2TaskOperationId
    payload: C2TaskPayload
```

`C2TaskCompiler` converts these control-plane DTOs into the separate V12
agent-wire DTOs defined only in PR-15. It must negotiate both payload and result
schema versions from `AgentCapabilitySetV12`; it cannot emit a task when either
capability is absent.

### 10.10. Result retrieval is mission-scoped and non-destructive

Использовать только canonical mission/resource-scoped API из §14.7:

```text
LIST_RESULTS  → read-only, never deletes/mutates
ACK_RESULTS   → explicit mutation, marks selected results acknowledged/consumed
PURGE_RESULTS → ADMIN-only bounded retention mutation
```

Никакой unscoped DB/control signature по одному `agent_id` не существует. Любой temporary `get_results` compatibility wrapper обязан принимать authenticated principal, `mission_id` и `agent_ref`, проходить тот же ACL path и оставаться non-destructive.

### 10.11. C2 DNS channel

```python
@dataclass(frozen=True)
class DNSChannelConfig:
    domain: str
    record_type: DNSRecordType
    listen_address: str
    listen_port: int


C2TransportConfig: TypeAlias = DNSChannelConfig
```

Until a second concrete transport leaf is added, `C2TransportConfig` has exactly
one legal variant. A future transport must extend the closed alias/decoder,
transport catalog, target schema and integration matrix in the same PR.

```python
@dataclass(frozen=True)
class DNSC2ChannelInputV2:
    target: str
    config: DNSChannelConfig
```

### 10.12. C2 generic channel router

```python
@dataclass(frozen=True)
class C2ChannelCreateInputV2:
    target: str
    transport: C2Transport
    config: C2TransportConfig


@dataclass(frozen=True)
class C2TransportRoute:
    transport: C2Transport
    child_action_id: str
    child_input_schema_id: str


@runtime_checkable
class C2TransportCatalog(Protocol):
    def require_route(self, transport: C2Transport) -> C2TransportRoute: ...
    def build_child_input(
        self,
        request: C2ChannelCreateInputV2,
        route: C2TransportRoute,
    ) -> DNSC2ChannelInputV2: ...
```

`C2TransportRoute` is owned once by PR-6 `core/c2/transport_catalog.py` and
contains no executable/provider callable. The catalog owns the closed builder
registry and rejects a route/schema mismatch.

### 10.13. Consistent deployment ownership

Choose one lifecycle owner:

```text
main-process DeploymentStore owns deployment:// resources
```

Daemon may keep an idempotent observability mirror, but daemon is not the lifecycle owner and cannot be solely responsible for late deployment cleanup.

Deployment metadata:

```text
deployment_ref
access_session_ref
remote cleanup recipe ref
artifact/enrollment/channel refs
mission/owner ACL
state/revision
mirror_state
```

Late cleanup uses main-process `DeploymentStore` and re-checks/accesses the required session or durable cleanup recipe.

Daemon mirror synchronization uses a local durable outbox:

```text
local deployment commit
→ outbox REGISTER_DEPLOYMENT_MIRROR
→ idempotent C2ControlClient call
→ mirror ACTIVE
```

Mirror failure does not transfer lifecycle ownership to daemon.

## 10.14. C2 cleanup input

```python
@dataclass(frozen=True)
class C2CleanupInputV2:
    resource_ref: str
    reason: C2CleanupReason
```

Caller не передаёт:

```text
resource_kind
lifecycle owner
backend name
```

Executor разрешает resource snapshot по resource_ref и получает kind/owner из
canonical store. Несовпадение store/type/authorization fail closed.

### 10.14A. Единственные `V2InputUnion` и `ActionRequestV2`

PR-6 is the first PR where all exact input classes exist. It therefore defines
the union exactly once in `core/actions/input_contracts.py`:

```python
V2InputUnion: TypeAlias = (
    PayloadKeyingInputV2
    | KerberosExtractInputV2
    | KerberosCrackInputV2
    | PassTheTicketInputV2
    | PassTheHashInputV2
    | CredentialDumpInputV2
    | RemoteExecInputV2
    | RemoteForwardInputV2
    | SSHChainInputV2
    | PivotProxyScanInputV2
    | C2EnrollmentIssueInput
    | C2TaskInputV2
    | C2DeployInputV3
    | DNSC2ChannelInputV2
    | C2ChannelCreateInputV2
    | C2CleanupInputV2
)
```

`SSHChainHopInputV2` and C2 task/deployment nested payload variants are members
of their owning top-level DTO and are not separate `ActionRequestV2` variants.

PR-6 then modifies `core/actions/request_v2.py` and creates the sole canonical
post-decoding request:

```python
ACTION_REQUEST_V2_SCHEMA_VERSION: Final = "2.0"


@dataclass(frozen=True)
class ActionRequestV2:
    request_id: str
    action_id: str
    mission_ref: str
    approval_ref: str | None
    precondition_fact_refs: tuple[str, ...]
    idempotency_key: str | None
    typed_input: V2InputUnion
    schema_version: Literal["2.0"] = field(
        default=ACTION_REQUEST_V2_SCHEMA_VERSION,
        init=False,
    )
```

Exact ownership:

```text
request_id              ← bounded phase-1 envelope
 action_id              ← injected from TypedActionCatalogEntry
 mission_ref            ← bounded business ref, not authority
 approval_ref           ← bounded business ref, not authority
 precondition_fact_refs ← bounded opaque refs
 idempotency_key        ← bounded optional key, action policy may require it
 typed_input            ← exact PR-6 decoder output only
 schema_version         ← executor-owned constant
```

No authority, snapshot, material, target, budget, lineage, command, parameters,
raw payload or handle field is legal. PR-6 also adds the child overload to the
single `_run_v2_internal` method from §4.8A. The decoder registry and target
extractor registry must bind every row from §2.4 to the exact runtime DTO type.

### 10.15. Production systemd identity

Reference production service uses stable identities:

```text
User=octopus-c2
Group=octopus-c2
SupplementaryGroups=octopus-c2-clients
DynamicUser is removed
```

Socket contract:

```text
owner=octopus-c2
socket group=octopus-c2-clients
mode=0660
runtime directory mode=0750
```

Installer/package scripts create users/groups and add approved client users to `octopus-c2-clients`.

Developer same-user mode may use `0600`, but it is a separate explicit profile and not the production readiness reference.

## 11. Router re-entry invariant

Routers have a separate capability surface and are never `TypedActionAdapterV2`
leaf calls:

```python
@runtime_checkable
class ChildExecutionFacadeV2(Protocol):
    @property
    def phase_lease(self) -> ProviderExecutePhaseLeaseV2: ...
    @property
    def used(self) -> bool: ...

    def run_selected_child(
        self,
        *,
        spec: ChildExecutionSpecV2,
    ) -> InvocationExecutionOutcomeV2: ...


@dataclass(frozen=True)
class ChildExecutionSpecV2:
    selected_child_action_id: str
    typed_input: V2InputUnion
    idempotency_key: str | None


@dataclass(frozen=True)
class CompositeRouteProgressV2:
    child_progress: ExecutionProgressReportV2


CompositeRouteOutcomeV2: TypeAlias = CompositeProviderResult | CompositeRouteProgressV2


@dataclass(frozen=True)
class ChildExecutionCompletionReceiptV2:
    parent_execution_id: str
    execution_graph_id: str
    selected_child_action_id: str
    child_execution_id: str
    child_result_ref: ExecutionResultRefV2
    committed_marker_digest: str
    receipt_digest: str


class CompositeChildPendingStateV2(str, Enum):
    WAITING_CHILD = "waiting_child"
    CLAIMED_FOR_RESUME = "claimed_for_resume"
    CHILD_READY = "child_ready"
    RESUMING_PARENT = "resuming_parent"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True)
class RecoveryExecutionBudgetPolicyV2:
    policy_id: str
    revision: int
    max_resume_seconds: int
    max_output_bytes: int
    max_child_depth: int
    policy_digest: str


@dataclass(frozen=True, repr=False, init=False)
class RecoveryExecutionBudgetLeaseV2:
    continuation_ref: str
    policy: RecoveryExecutionBudgetPolicyV2
    budget: ExecutionBudget = field(repr=False, compare=False)
    authority_provenance_id: str


@dataclass(frozen=True, repr=False)
class RecoveryExecutionAuthorityBundleV2:
    budget_lease: RecoveryExecutionBudgetLeaseV2
    controller_binding: CancellationControllerBindingV2


@runtime_checkable
class RecoveryExecutionBudgetAuthorityV2(Protocol):
    def issue_for_composite_resume(
        self,
        *,
        pending_ref: CompositeChildPendingRefV2,
        policy: RecoveryExecutionBudgetPolicyV2,
        cancellation: CancellationRecoveryRecordV2,
    ) -> RecoveryExecutionAuthorityBundleV2: ...
    def validate(
        self,
        authority: RecoveryExecutionAuthorityBundleV2,
        *,
        pending_ref: CompositeChildPendingRefV2,
    ) -> ExecutionBudget: ...


@dataclass(frozen=True)
class CompositeRouteContinuationDraftV2:
    parent_request: ActionRequestV2
    parent_request_digest: str
    parent_policy_snapshot_digest: str
    parent_principal_ref: str
    parent_principal_revision: int
    parent_mission_ref: str
    parent_mission_revision: int
    parent_approval_graph_recovery_ref: ApprovalGraphRecoveryRefV2
    original_ingress_recovery_ref: InvocationLeaseRecoveryRefV2
    cancellation_recovery_ref: CancellationRecoveryRefV2
    router_mount_revision: int
    router_mount_digest: str
    router_provider_generation: str
    parent_readiness_snapshot_digest: str
    parent_checkout_recovery_ref: CheckoutRecoveryRefV2
    parent_scope_recovery_ref: InvocationScopeRecoveryRefV2
    parent_coordinator_recovery_ref: ExecutionCommitRecoveryRefV2
    parent_finalization_intent_ref: InvocationFinalizationIntentRefV2
    recovery_budget_policy: RecoveryExecutionBudgetPolicyV2
    selected_child_spec: ChildExecutionSpecV2
    continuation_digest: str


@dataclass(frozen=True)
class CompositeChildPendingRefV2:
    reference: str
    revision: int
    parent_execution_id: str
    record_digest: str


@dataclass(frozen=True)
class CompositeChildPendingRecordV2:
    pending_ref: CompositeChildPendingRefV2
    state: CompositeChildPendingStateV2
    parent_execution_id: str
    parent_transaction_id: str
    execution_graph_id: str
    selected_child_action_id: str
    child_execution_id: str
    child_progress_ref: str
    child_progress_revision: int
    child_progress_digest: str
    child_report_ownership_ref: ExecutionReportOwnershipRefV2
    continuation: CompositeRouteContinuationDraftV2
    resume_idempotency_key: str
    resume_claim_id: str | None
    resume_claim_expires_at_utc: float | None
    resume_claimer_instance_id: str | None
    resume_claimer_boot_id: str | None
    resume_fencing_token: int


@dataclass(frozen=True)
class CompositeChildPendingDraftV2:
    parent_execution_id: str
    parent_transaction_id: str
    execution_graph_id: str
    selected_child_action_id: str
    child_execution_id: str
    child_progress: ExecutionProgressReportV2
    child_report_ownership_ref: ExecutionReportOwnershipRefV2
    continuation: CompositeRouteContinuationDraftV2
    resume_idempotency_key: str


def canonical_composite_route_continuation_digest(
    draft: CompositeRouteContinuationDraftV2,
) -> str: ...


def canonical_composite_child_pending_record_digest(
    record: CompositeChildPendingRecordV2,
) -> str: ...


@runtime_checkable
class CompositeChildPendingStoreV2(Protocol):
    def begin(
        self,
        draft: CompositeChildPendingDraftV2,
    ) -> CompositeChildPendingRecordV2: ...
    def require(
        self,
        reference: CompositeChildPendingRefV2,
    ) -> CompositeChildPendingRecordV2: ...
    def claim_for_resume(
        self,
        reference: CompositeChildPendingRefV2,
        *,
        expected_revision: int,
        claim_id: str,
        claim_expires_at_utc: float,
        claimer_instance_id: str,
        claimer_boot_id: str,
        expected_fencing_token: int,
    ) -> CompositeChildPendingRecordV2: ...
    def release_claim_to_waiting(
        self,
        reference: CompositeChildPendingRefV2,
        progress: ExecutionProgressReportV2,
        *,
        claim_id: str,
        fencing_token: int,
    ) -> CompositeChildPendingRecordV2: ...
    def renew_claim(
        self,
        reference: CompositeChildPendingRefV2,
        *,
        claim_id: str,
        fencing_token: int,
        new_expires_at_utc: float,
    ) -> CompositeChildPendingRecordV2: ...
    def mark_child_ready(
        self,
        reference: CompositeChildPendingRefV2,
        receipt: ChildExecutionCompletionReceiptV2,
        *,
        claim_id: str,
        fencing_token: int,
    ) -> CompositeChildPendingRecordV2: ...
    def begin_parent_resume(
        self,
        reference: CompositeChildPendingRefV2,
        *,
        claim_id: str,
        fencing_token: int,
    ) -> CompositeChildPendingRecordV2: ...
    def checkpoint_child_progress(
        self,
        reference: CompositeChildPendingRefV2,
        progress: ExecutionProgressReportV2,
    ) -> CompositeChildPendingRecordV2: ...
    def complete(
        self,
        reference: CompositeChildPendingRefV2,
        report: ActionExecutionReportEnvelopeV2,
        finalization_intent: InvocationFinalizationIntentRecordV2,
        *,
        claim_id: str,
        fencing_token: int,
    ) -> CompositeChildPendingRecordV2: ...
    def fail(
        self,
        reference: CompositeChildPendingRefV2,
        report: ActionExecutionReportEnvelopeV2,
        *,
        claim_id: str,
        fencing_token: int,
    ) -> CompositeChildPendingRecordV2: ...
    def list_pending(self) -> tuple[CompositeChildPendingRefV2, ...]: ...
```


`CompositeChildPendingStoreV2.begin()` accepts a digest-free draft and alone
mints `pending_ref`, revision, `WAITING_CHILD` state and record digest. Every
mutation consumes `record.pending_ref` at its exact latest revision and returns
a new record carrying the newly store-issued ref; callers never manufacture or
copy revision/digest fields. The canonical record digest covers
`pending_ref.reference/revision` plus every non-ref record field and excludes
only `pending_ref.record_digest`. Claims use durable UTC expiry together with
instance/boot IDs and a monotonically increased fencing token; mutation under a
claim requires both claim ID and fencing token. `renew_claim()` is bounded by
the stored recovery policy, and an expired claim may be reclaimed only
through a higher fencing token.

The pending store passes its minted ref to
`ExecutionContinuationRecoveryStoreV2.reserve_handoff()`. Exact ordered durable
writes are: pending begin/read-back → reserve handoff ref → attach RESERVED ref
to intent → CAS custody with the four owner refs → checkpoint the returned
CUSTODY_TRANSFERRED revision into intent → publish progress. A crash at any gap
is resolved by the intent plus `list_incomplete()`; no cross-store ACID claim is
made. Only then does the normal outer-finally skip
parent abort/checkout/scope/graph close; it consumes the original ingress once.
Independent intent recovery sees the same continuation ref and delegates to the
composite reconciler rather than cleaning those owners. Completion/failure
atomically binds the same final envelope and marks both the pending record and
intent continuation COMPLETED using ordered idempotent writes. Completion first
publishes/read-backs the parent envelope, then completes the continuation store,
then completes/checkpoints the intent; replay uses the same envelope/ref. A
half-handoff or half-completion remains progress/pending and recovery continues
from the last read-back record.


```python
@dataclass(frozen=True, repr=False)
class BoundCompositeRouterContextV2:
    reference_snapshots: tuple[ReferenceMetadataSnapshot, ...]
    fact_snapshots: tuple[TrustedFactSnapshot, ...]
    targets: tuple[ExtractedActionTarget, ...]
    readiness: ProviderReadinessSnapshot
    budget: ExecutionBudget
    lineage: ExecutionLineage
    phase_lease: ProviderExecutePhaseLeaseV2 = field(repr=False, compare=False)
    child_execution: ChildExecutionFacadeV2 = field(repr=False, compare=False)


@runtime_checkable
class TypedCompositeRouterV2(Protocol):
    adapter_api_version: Literal[2]
    descriptor: ActionDescriptorV2

    def check_bound(
        self,
        request: ActionRequestV2,
        context: BoundProviderCheckContext,
    ) -> ActionCheckResultV2: ...

    def route_bound(
        self,
        request: ActionRequestV2,
        context: BoundCompositeRouterContextV2,
    ) -> CompositeRouteOutcomeV2: ...

    def verify_bound(
        self,
        request: ActionRequestV2,
        result: ProviderResultReadViewV2,
        context: BoundProviderVerificationContext,
    ) -> ActionVerificationResultV2: ...
```

The exact `ProviderCallBoundary.invoke_route(..., *, _phase_controller)` method
is the single existing-class modification specified in §12.2; this section does
not define another boundary class.

The context has no `BoundMaterialBundle`, attempt lease, staging, participant
registration, sensitive factory, mutable scope or daemon/backend client.
`ChildExecutionFacadeV2` and every router context method check one boundary-owned
phase lease. `ProviderCallBoundary.invoke_route(...)` enforces the same deadline,
cancellation and output bounds as leaf execute and revokes the lease in its own
`finally`; a cached child facade cannot run after `route_bound` returns. Router
check/verify remain mandatory per §2.5 and use the same read-only contexts as a
leaf.

Before constructing child authority the facade requires: phase lease active;
selected child belongs to the parent router's closed route/candidate registry;
selected ID differs from parent; `typed_input` runtime variant and schema ID
match that child descriptor; max depth/budget allow re-entry; the parent approval
graph permits the edge. Any mismatch fails before child catalog/readiness detail
is exposed.
The facade is single-use: its first accepted spec atomically marks it used;
denial/unavailability is returned as that one child outcome and the router may
not submit a second child. Candidate filtering therefore happens before the
facade call and never becomes active fallback.
The concrete facade privately records exactly one store-issued
`ChildExecutionCompletionReceiptV2` only when the actual child final report
passes `require_successful_committed_result_ref()`. The receipt never enters the
router protocol/context. After route return the boundary/executor requires the
composite action/execution/ref triple to equal that private receipt and verifies
parent/graph/marker digest; zero, multiple or mismatched receipts fail closed.
Public `ExecutionResultRefV2` fields copied by router code are never authority.
If the child returns progress, the facade first persists a
`CompositeChildPendingRecordV2` binding the parent transaction/graph, exact
child spec, child execution, progress ref and report-ownership ref. Its closed
continuation stores the parent request (opaque refs only), policy/readiness
digests and every parent recovery ref required for post-route verify/project;
it stores no live lease, material or capability. `begin()` canonicalizes and
read-backs a WAITING record before parent progress is published. Only then
may the parent publish `CompositeRouteProgressV2`. The composite reconciler
CAS-claims the record once with a stable claim/idempotency key, reopens the
fenced parent and uses that record to query the child under executor authority.
A terminal child
failure finalizes the parent without a result; a final committed child is
validated, converted to the private `ChildExecutionCompletionReceiptV2`, and
resumes the same fenced parent at verify/result staging exactly once. A missing,
changed, stale-revision or multiply-consumed pending record fails closed;
process restart enumerates `list_pending()`, and the router itself is never
re-entered.

On delayed resume the original ingress lease and monotonic deadline are never
reused. The composite reconciler acts only under executor recovery authority:
it first re-reads `cancellation_recovery_ref`; CANCEL_REQUESTED/CANCELLED
forbids parent VERIFY/router re-entry and propagates cancellation/containment
through the graph-scoped token; it does not finalize or release parent custody
while the child is still termination/reconciliation pending, detached or
IN_DOUBT. The parent remains progress until the child ownership query proves a
terminal envelope or durable quiesced/terminal containment. Only then may the
parent finalize CANCELLED, and it never consumes a later child success result.
The same containment-before-parent-finalization rule applies to principal,
mission, approval, mount, provider or readiness revocation. Otherwise it
CAS-claims the pending record, re-resolves the stored principal and mission
refs and requires the exact stored revisions, validates the approval-graph
recovery ref/ownership, and requires the current router mount revision/digest,
provider generation and readiness identity to match the continuation. A
store-owned `RecoveryExecutionBudgetAuthorityV2` then mints one bounded
`RecoveryExecutionAuthorityBundleV2` from the persisted policy. It re-reads the
current ACTIVE record, creates a private controller for the stable token ID and
calls `bind_live_controller()`; that CAS both rechecks revision/state and
returns the binding carried by the bundle. A racing cancel signals/fails the
binding immediately. The resulting budget uses only that controller's token;
the reconciler rechecks current cancellation immediately before VERIFY and
unbinds the binding in `finally`. Callers and routers cannot construct or widen
it. The reconciler builds a fresh VERIFY phase call
plan and journal record under that budget. If authority/readiness/mount binding
changed, it fences further parent work and finalizes failure only after the
child containment rule above, without rerunning the router; if the
child is still progress, it durably checkpoints the new progress and returns
the claim to WAITING. Approval-graph custody stays with the reconciler until the
parent final envelope and intent completion are durable; it closes the graph
only when the stored recovery ref has `owner=True` (a nested router may have
`owner=False`).

Composite/router identity не вызывает:

```text
leaf provider function
daemon handler
C2ControlClient concrete method
material resolver
```

Router обязан:

```text
1. выбрать child action ID
2. создать только ChildExecutionSpecV2 с selected action, closed typed input и
   optional derived idempotency key
3. вызвать `context.child_execution.run_selected_child(spec=...)`
4. executor-owned facade generates child request_id, inherits mission/approval/
   fact refs, creates ChildIngressLease/ChildExecutionBridge/lineage and re-enters
   `_run_v2_internal(...)`; router never sees or constructs those authority objects
5. exhaustively match the child outcome: only an
   `ActionExecutionReportEnvelopeV2` whose store ref/revision/digest were
   revalidated may call
   `envelope.report.require_successful_committed_result_ref()` and produce
   `CompositeProviderResult`; `ExecutionProgressReportV2` produces
   `CompositeRouteProgressV2`, then parent progress with no verify/result
   participant and never a synthetic child ref; `assert_never` closes the union
```

### `ad_remote_execution`

```text
trusted service fact snapshots
→ ProviderSelector
→ ad_smbexec | ad_winrm_exec | ad_dcom_exec
→ child ActionRequest
→ ActionExecutor
```

До attempt можно пропускать leaf, если он:

```text
unconfigured
unmounted
unavailable
не удовлетворяет request preconditions
```

После фактического attempt automatic active fallback запрещён.

### `c2_channel_create`

```text
C2TransportCatalog
→ DNS maps to dns_c2_channel
→ child typed input
→ child ActionRequest
→ ActionExecutor
→ dns_c2_channel leaf
```

`c2_channel_create` не обращается к daemon/client напрямую.

---

## 12. Совместимость с существующими 96 adapters

### 12.1. Не менять V1 signature глобально

Существующий runtime class остаётся `core.actions.base.ActionAdapter`. Единственный
`ActionAdapterV1` alias объявлен в PR-1/§2.1; этот раздел только импортирует его
и не объявляет alias или base class повторно.

Его существующие methods остаются без изменения:

```text
check(request) -> ActionCheckResult
execute(request) -> Any
verify(request, result: ExecutionResult) -> ActionVerificationResult
cleanup(request, result: ExecutionResult | None) -> ActionCleanupResult
```

96 существующих adapters продолжают наследовать `ActionAdapter` и работать через
V1 path. Ни один существующий construction site не обязан переименовывать base
class в `ActionAdapterV1`.

### 12.2. Independent V2 check/execute/verify protocols

V2 does not inherit V1. Three phases have distinct capability surfaces.

```python
@dataclass(frozen=True, repr=False)
class BoundProviderCheckContext:
    reference_snapshots: tuple[ReferenceMetadataSnapshot, ...]
    fact_snapshots: tuple[TrustedFactSnapshot, ...]
    targets: tuple[ExtractedActionTarget, ...]
    readiness: ProviderReadinessSnapshot
    budget: ExecutionBudget
    lineage: ExecutionLineage


@dataclass(frozen=True, repr=False)
class ParticipantRegistrationReadViewV2:
    registration_ref: ParticipantRegistrationRefV2
    registration_schema_id: str
    payload_digest: str
    prepare_depends_on: tuple[ParticipantRegistrationRefV2, ...]
    commit_depends_on: tuple[ParticipantRegistrationRefV2, ...]


ProviderVisibleResultDraftRefV2: TypeAlias = (
    ObservationDraftRefV2 | ArtifactDraftRefV2 | ManagedResourceDraftRefV2 | SensitiveBatchDraftRefV2
)


@dataclass(frozen=True, repr=False)
class ProviderResultReadViewV2:
    result_schema_id: str
    result_kind: ProviderResultKind
    header: ProviderResultHeaderV2
    draft_refs: tuple[ProviderVisibleResultDraftRefV2, ...]
    registration_views: tuple[ParticipantRegistrationReadViewV2, ...]
    linked_result_refs: tuple[ExecutionResultRefV2, ...]
    result_digest: str


def canonical_provider_result_read_view_digest(
    view: ProviderResultReadViewV2,
) -> str:
    """RFC-8785 tagged digest over all exact fields except result_digest."""
    ...


class ProviderResultReadViewFactoryV2:
    """Executor-only factory after sensitive normalization and lease revocation."""

    def create(
        self,
        *,
        result_schema_id: str,
        result_kind: ProviderResultKind,
        header: ProviderResultHeaderV2,
        draft_refs: tuple[ProviderVisibleResultDraftRefV2, ...],
        registration_views: tuple[ParticipantRegistrationReadViewV2, ...],
        linked_result_refs: tuple[ExecutionResultRefV2, ...],
    ) -> ProviderResultReadViewV2: ...


@dataclass(frozen=True, repr=False)
class BoundProviderVerificationContext:
    reference_snapshots: tuple[ReferenceMetadataSnapshot, ...]
    fact_snapshots: tuple[TrustedFactSnapshot, ...]
    targets: tuple[ExtractedActionTarget, ...]
    budget: ExecutionBudget
    lineage: ExecutionLineage
```

The read-view factory canonicalizes the bounded closed fields, computes the
digest itself and immediately read-back verifies it; callers/providers never
supply `result_digest`. Whenever
`DecisionTraceRecordV2.outcome_phase=PROVIDER_RESULT`, its
`provider_result_digest` equals this digest. Pre-provider decode/policy/check/
readiness/cancellation failures carry `None`, never a synthetic digest.

Neither check nor verification context contains `InvocationScope`, live/secret
material, `ProviderStagingFacade`, participant registration, or transaction
methods.
The executor fills `linked_result_refs` with exactly the successful committed
child ref for `CompositeProviderResult` and `()` for every other variant;
verify receives no result-store lookup capability.
It also never sees secret/credential/fact/audit/trace/execution-result/
participant-payload drafts or registrations. Registration views are only those
directly represented by `ProviderVisibleResultDraftRefV2`; the complete
`ParticipantDraftRefV2` topology remains executor/projector-only.

```python
@dataclass(frozen=True)
class ActionCheckResultV2:
    passed: bool
    reason_codes: tuple[str, ...]
    checked_at_monotonic: float


@dataclass(frozen=True)
class ActionVerificationResultV2:
    verified: bool
    reason_codes: tuple[str, ...]
    verified_at_monotonic: float


@runtime_checkable
class SupportsCheckBoundV2(Protocol):
    def check_bound(
        self,
        request: ActionRequestV2,
        context: BoundProviderCheckContext,
    ) -> ActionCheckResultV2: ...


@runtime_checkable
class TypedActionAdapterV2(Protocol):
    adapter_api_version: Literal[2]
    descriptor: ActionDescriptorV2

    def execute_bound(
        self,
        request: ActionRequestV2,
        invocation: BoundProviderInvocationContext,
    ) -> ProviderResult: ...


@runtime_checkable
class SupportsVerifyBoundV2(Protocol):
    def verify_bound(
        self,
        request: ActionRequestV2,
        result: ProviderResultReadViewV2,
        context: BoundProviderVerificationContext,
    ) -> ActionVerificationResultV2: ...
```

PR-7 modifies the single PR-5 `ProviderCallBoundary` owner by adding the
following methods; it must not redeclare the class:

```text
ProviderCallBoundary.invoke_check(
    adapter: SupportsCheckBoundV2,
    request: ActionRequestV2,
    context: BoundProviderCheckContext,
    *,
    call_plan: ProviderPhaseCallPlanV2,
    call_record: ProviderCallRecoveryRecordV2,
) -> ActionCheckResultV2

ProviderCallBoundary.invoke_execute(
    adapter: TypedActionAdapterV2,
    request: ActionRequestV2,
    invocation: BoundProviderInvocationContext,
    *,
    call_plan: ProviderPhaseCallPlanV2,
    call_record: ProviderCallRecoveryRecordV2,
    _phase_controller: _ProviderExecutePhaseLeaseControllerV2,
) -> ProviderResult

ProviderCallBoundary.invoke_route(
    adapter: TypedCompositeRouterV2,
    request: ActionRequestV2,
    context: BoundCompositeRouterContextV2,
    *,
    call_plan: ProviderPhaseCallPlanV2,
    call_record: ProviderCallRecoveryRecordV2,
    _phase_controller: _ProviderExecutePhaseLeaseControllerV2,
) -> CompositeRouteOutcomeV2

ProviderCallBoundary.invoke_verify(
    adapter: SupportsVerifyBoundV2,
    request: ActionRequestV2,
    result: ProviderResultReadViewV2,
    context: BoundProviderVerificationContext,
    *,
    call_plan: ProviderPhaseCallPlanV2,
    call_record: ProviderCallRecoveryRecordV2,
) -> ActionVerificationResultV2
```

PR-7 preserves the private controller arguments from PR-5 and uses identity
checks before activation; neither controller is exposed to adapter code.
It also preserves the PR-5 call-plan and recovery-record arguments on every
phase; check/execute/
route/verify receive separate phase call IDs but the same execution/provider/
mount generation and monotonically narrowed deadline.
Both ephemeral timestamps use the executor/runner's `time.monotonic()` domain
and are overwritten/validated at the boundary; a provider-supplied wall-clock
or non-monotonic value is never durable phase evidence.


Exact lifecycle:

```text
1. deep authorization and atomic snapshot/reference checkout, without material open;
2. if descriptor.check_policy=REQUIRED, require SupportsCheckBoundV2 and call
   ProviderCallBoundary.invoke_check(); failure stops before attempt reservation;
3. reserve attempt, run final readiness, open fenced material, assert current,
   and atomically start the attempt;
4. call ProviderCallBoundary.invoke_execute(); execute is the only provider phase
   allowed to create transaction-private drafts and register closed participant specs;
5. revoke the execute phase lease, internally consume/stage any core-owned
   sensitive handle, normalize the exact variant, then construct a read-only
   view over typed draft refs and registration descriptors (never live payloads,
   handles or capabilities);
6. if descriptor.verify_policy=REQUIRED, require SupportsVerifyBoundV2 and call
   ProviderCallBoundary.invoke_verify() with that read-only view; verification can
   approve/reject but cannot add, replace or publish drafts/participants;
7. after successful verification no provider method is invoked again. Only the
   executor-owned coordinator may run participant prepare/decision/commit/finalize
   and publish the committed result.
```

For `COMPOSITE_ROUTER`, steps 3–4 are replaced by
`authorize_router_step → invoke_route`; no attempt or material is created.
`invoke_route` owns/revokes the router phase lease, while each selected child
re-enters the full leaf lifecycle. Parent composite result staging is internal
and occurs only after router verify succeeds.

`ProviderCallBoundary` is the sole caller of check/leaf-execute/router-route/
verify phases and enforces the
same cancellation/deadline/output budget. `verify_bound` cannot publish a
resource by construction. Missing required protocol, unexpected method,
verification failure, or an attempt to return a draft from verify fails closed.

### 12.3. Executor dispatch

```text
adapter_api_version=1 → существующий lifecycle без изменения
adapter_api_version=2 → canonical V2 authorization/checkout/scope/transaction path
```

V1 adapters не получают:

```text
BoundProviderInvocationContext
BoundMaterialBundle
InvocationScope
ExecutionCommitCoordinator
ProviderStagingFacade
V2 snapshots
```

### 12.4. Cleanup compatibility

```text
V1 → существующий adapter.cleanup()
V2 → InvocationScope finally + executor-owned ExecutionCommitCoordinator
```

V2 adapter не использует старый generic `cleanup()` для retained resource lifecycle.

### 12.5. Catalog invariants

```text
116 identities сохраняются
96 V1 adapters продолжают проходить текущие tests
20 identities мигрируют на V2
одна identity имеет ровно один active adapter owner
LEAF entry implements TypedActionAdapterV2 and never TypedCompositeRouterV2
COMPOSITE_ROUTER entry implements TypedCompositeRouterV2 and never leaf execute
schema/semantic/mount matrices join exactly по action_id
aliases normalize before dispatch and have no V1/V2 collision
all required_fact_type_ids resolve in ActionPreconditionRegistryV2
```

---

## 13. Общие обязательные требования для PR-1–PR-20

Every new or modified typed Python module begins with
`from __future__ import annotations`. Every PR, including foundation PR-1–PR-7,
adds/updates its Python 3.10 import-smoke inventory and imports every
first-party module in dependency order; normative snippets may therefore use
forward references without runtime `NameError`. This rule does not excuse an
undefined owner or circular runtime import.

Каждый implementation PR обязан использовать:

```text
versioned ActionCatalogEntry + V2 ProviderMountSpec ownership
non-serializable IngressInvocationLease
IngressSessionStore checkout
principal derived only from authenticated ingress session
mission snapshot
ApprovalExecutionLease + execution_graph_id
router parent no-consume semantics
concrete leaf single-use attempt commit
manual operator gate
approval action-graph/stage/target/operation binding
trusted fact refs + TrustedFactDecoder
executor-owned ActionTargetExtractorRegistry
initial readiness + post-checkout/pre-material immediate readiness recheck
atomic ReferenceCheckoutCoordinator
metadata.reference == authorization.reference invariant
InvocationScope outer finally
revocable execute-phase lease + restricted provider scope/staging/participant facades
provider facade cannot register executor-owned result/audit/sensitive/store participants
executor-owned ExecutionCommitCoordinator
transactional sensitive ingestion
transactional managed-resource stage/commit/rollback
V2 adapter API без изменения 96 V1 adapters
refs-only ExecutionResult
AST/import boundary: V2 adapters and core/providers cannot import SecretStore,
CredentialStore, FactStore, ArtifactStore, session/route stores, C2ControlClient,
ExecutionCommitCoordinator or global getters; only a narrowly reviewed backend
allowlist may cross infrastructure boundaries
```

В каждом provider PR добавить shared tests:

```text
missing authenticated ingress → denied
caller principal_ref/subject_id spoof → denied
revoked/expired ingress session → denied
ingress peer/channel binding mismatch → denied
principal/ingress mismatch → denied

caller approved=True без approval snapshot → denied
non-operator principal → denied
missing approval_ref → denied
expired/revoked approval → denied
approval action mismatch → denied
approval action-graph mismatch → denied
approval kill-chain stage mismatch → denied
disabled config stage → denied
approval target mismatch → denied
approval operation mismatch → denied

max_uses=1 concrete action consumes once
router parent does not consume
selected concrete child consumes once
pre-attempt failure does not consume
post-attempt failure remains consumed
second child attempt denied

metadata.reference != authorization.reference → denied
reference revision race → denied
authorization revision race → denied
ingress revision race → denied
fact revision race → denied
approval lease revision race → denied

readiness changes to unavailable after snapshot/reference checkout but before material open → no provider attempt
approval use not consumed on readiness recheck failure
cleanup finally executes on success/exception/timeout/cancellation

sensitive ingestion staging participates through the executor-owned sensitive participant
late sensitive/result/audit error rolls back resources and staged refs
rolled-back sensitive refs are not queryable
returned managed resource becomes visible only after required cross-process finalization ACKs and final COMMITTED execution journal
```

Для C2-related PR дополнительно:

```text
no typed task → raw command downgrade
agent task protocol/capability precondition enforced
no builder auto-issue enrollment
artifact/enrollment/channel/profile binding enforced
deployment lifecycle owner explicit
LIST_RESULTS non-destructive
ACK_RESULTS mutating and RBAC-gated
```

## 13.1. Canonical generated dependency-lock regeneration matrix

`requirements/locks/manifest.json` and `scripts/lock_requirements.py` are the
canonical dependency graph. Any source requirement change regenerates every
profile whose `PROFILE_INPUTS` contains that source, for `cp310`, `cp311` and
`cp312`, followed by manifest regeneration.

Exact impact matrix:

| Changed source | Profiles to regenerate for all three Python targets |
|---|---|
| `requirements/runtime.txt` | `runtime`, `c2`, `reporting`, `osint-browser`, `test`, `mysql`, `external-tools`, `platform`, `full` |
| `requirements/c2.txt` | `c2`, `test`, `full` |
| `requirements/reporting.txt` | `reporting`, `test`, `full` |
| `requirements/osint-browser.txt` | `osint-browser`, `full` |
| `requirements/dev.txt` | `test`, `full` |
| `requirements/mysql.txt` | `mysql`, `full` |
| `requirements/external-tools.txt` | `external-tools`, `full` |
| `requirements/platform.txt` | `platform`, `full` |

Every regeneration also modifies:

```text
requirements/locks/manifest.json
```

Required commands:

```text
python scripts/lock_requirements.py update
python scripts/lock_requirements.py validate
python scripts/lock_requirements.py check
```

The PR ledger may list generated files by profile glob instead of manually
omitting transitive locks. CI adds a test that recomputes profile/source impact
from `PROFILE_INPUTS` and rejects an incomplete changed-file set or stale
manifest input hashes.

The sole compact path grammar is one non-nested brace-list segment containing
comma-separated literal filenames, for example `{runtime,c2,full}.txt`.
The ledger parser expands it to lexicographically sorted exact paths before all
ownership/existence/changed-file checks. Nested braces, ranges, wildcards,
empty/duplicate alternatives and brace syntax outside generated lock paths are
invalid. Thus every compact lock entry has one deterministic expanded set; it
is not interpreted as a Python glob or shell expression.



Generated-lock completeness is an enforced contract, not documentation only.
Create in PR-6:

```text
scripts/quality/dependency_lock_impact_gate.py
tests/test_dependency_lock_impact_matrix.py
```

The gate imports `PROFILE_INPUTS` from `scripts/lock_requirements.py`, computes
all affected `(target, profile)` lock paths for each changed source requirement,
and requires both those files and `requirements/locks/manifest.json` to change.
No hand-written subset is accepted.

Exact required impact for changes used by this plan:

```text
requirements/runtime.txt
    → 9 profiles × cp310/cp311/cp312 = 27 lock files + manifest

requirements/external-tools.txt
    → external-tools/full × 3 = 6 lock files + manifest

requirements/dev.txt
    → test/full × 3 = 6 lock files + manifest
```

Required tests:

```text
test_runtime_requirement_change_requires_all_27_locks_and_manifest
test_external_tools_change_requires_external_tools_full_all_targets
test_dev_change_requires_test_full_all_targets
test_manifest_input_hashes_match_changed_requirement_sources
test_lock_impact_gate_uses_profile_inputs_not_manual_allowlist
```

## Canonical file creation ownership

Before PR-1 this document is an untracked implementation input. PR-1 has its
sole CREATE ownership and commits
`docs/architecture/typed-providers-implementation-plan-v6.13.md`; from the
PR-1 tree onward its CREATE/MODIFY declarations are the authoritative ledger.
PR-1 also creates
`scripts/quality/provider_plan_ledger_gate.py` and
`tests/test_provider_plan_ledger.py`; the test parses this file, so the ledger is
not attachment-only or dependent on chat history. Enforce one create owner per
path:

```text
PR-2 creates core/actions/composite_execution.py
PR-7 modifies core/actions/composite_execution.py
PR-12 modifies core/actions/composite_execution.py
PR-6 creates core/c2/agent_task_models.py
PR-15 modifies core/c2/agent_task_models.py
PR-6 creates core/c2/transport_catalog.py
PR-18 modifies core/c2/transport_catalog.py
PR-11 creates core/execution/processes.py
```

Add `test_pr_file_ledger_has_single_create_owner` to reject duplicate CREATE ownership and MODIFY-before-CREATE errors.
Add `test_plan_path_has_pr1_create_owner_and_no_modify_before_create` for the
bootstrap rule itself.
Add these exact parser ratchets:

```text
test_ledger_expands_single_generated_lock_brace_list_exactly
test_ledger_rejects_nested_braces_ranges_wildcards_empty_and_duplicate_alternatives
test_ledger_rejects_braces_outside_requirements_locks
test_expanded_lock_paths_participate_in_duplicate_and_existence_checks
test_pr20_sentinels_only_final_in_pr20_create_modify_and_contribute_zero_paths
test_ledger_rejects_duplicate_or_misplaced_pr20_sentinel
test_final_ledger_rejects_pr20_sentinel
```

Ledger semantics:

```text
quality/provider-mounts.json → GENERATE only, no CREATE owner
tests/test_router_reentry_contract.py → CREATE in PR-12, MODIFY only after PR-12
core/execution/processes.py → path is absent before PR-11 and has exactly one CREATE owner in PR-11
generated paths are tracked separately from source CREATE paths
```

# PR-1. Canonical state ownership, provider manifest и legacy `provider`/`provider_mounted` migration

## Цель

Ввести versioned `LegacyActionDescriptorV1 | ActionDescriptorV2`, оставить provider wiring 96 V1 adapters в V1 compatibility path и создать отдельный 20-entry `ProviderMountRegistry` только для V2 без ложных file assumptions.

## CREATE

```text
docs/architecture/typed-providers-implementation-plan-v6.13.md
core/actions/provider_mounts.py
core/actions/provider_state.py
core/actions/adapter_registration.py
core/actions/schema_bindings.py
core/actions/semantic_bindings.py
core/actions/legacy_descriptor_decoder.py
core/tools/manual_actions.py
scripts/quality/provider_mount_gate.py
scripts/quality/provider_legacy_field_inventory.py
scripts/quality/provider_plan_ledger_gate.py
tests/test_provider_mount_manifest.py
tests/test_provider_state_ownership.py
tests/test_typed_adapter_registration_v2.py
tests/test_v2_schema_binding_matrix.py
tests/test_provider_legacy_field_inventory.py
tests/test_action_descriptor_versions.py
tests/test_v2_semantic_binding_matrix.py
tests/test_provider_plan_ledger.py
```

`core/tools/manual_actions.py` является новым файлом. Не указывать его как существующий `MODIFY`.

## MODIFY

```text
core/actions/models.py
core/actions/catalog.py
core/actions/base.py
core/actions/adapters.py
core/actions/adapters_c2.py
core/actions/adapters_pivot.py
core/actions/adapters_evasion.py
core/actions/adapters_kerberos.py
core/actions/adapters_ad_lateral.py
core/actions/adapters_ad_credential.py
core/ai/runtime.py
core/ai/tool_registry.py
core/tools/__init__.py
core/tools/registry.py
core/tools/quarantined.py
README.md
docs/architecture/action-lifecycle.md
docs/architecture/contracts-and-ownership.md
tests/test_action_catalog.py
tests/test_action_catalog_coverage.py
tests/test_action_provider_contracts.py
tests/test_action_adapters_new.py
tests/test_action_base_coverage.py
tests/test_architecture_ratchet.py
tests/test_high_risk_action_contracts.py
tests/test_runtime_plugin_catalog_contract.py
tests/test_unified_tool_runtime_contract.py
```

Перед implementation запустить inventory script и дополнить список всеми фактическими consumers.

## GENERATE

```text
quality/provider-mounts.json
```

JSON snapshot генерируется из `ProviderMountRegistry`; ручное редактирование запрещено.

## Реализация

1. Существующий V1 `ActionKind` не изменять. Добавить отдельный `ExecutionNodeKind` (`LEAF`, `COMPOSITE_ROUTER`) и `ProviderTransport` (`IN_PROCESS`, `LOCAL_DAEMON_IPC`, `CHILD_EXECUTOR`).
2. Зафиксировать текущий descriptor contract как `LegacyActionDescriptorV1`. Существующий import-name `ActionDescriptor` временно остаётся alias для него, чтобы не переписывать 96 V1 construction sites.
3. Добавить независимый `ActionDescriptorV2` для 20 typed identities.
4. В `core/actions/adapter_registration.py` объявить `ActionAdapterV1: TypeAlias = ActionAdapter`; не создавать новый V1 base class и не менять существующие 96 subclasses.
5. Добавить минимальный `TypedActionAdapterRegistrationV2` с полями `adapter_api_version` и `descriptor`; PR-1 catalog не импортирует future execution protocol из PR-7.
6. Добавить:
   ```python
   ActionDescriptorUnion = LegacyActionDescriptorV1 | ActionDescriptorV2
   ```
7. Добавить tagged catalog entries:
   ```text
   LegacyActionCatalogEntry
   TypedActionCatalogEntry
   ```
8. `ActionCatalog.resolve_entry()` возвращает union и не скрывает adapter API version.
9. Сделать schema/semantic binding matrices единственным declarative source, а
   `ActionDescriptorV2` — единственной immutable runtime projection:
   ```text
   kind
   execution_node_kind
   manual_gate
   check_policy
   verify_policy
   capability_class
   risk_class
   killchain_stage
   required_fact_type_ids
   aliases
   input_schema_id
   result_schema_id
   ```
10. Сделать `ProviderMountSpec` единственным владельцем V2 wiring:
   ```text
   configured
   mounted
   typed_action_supported
   raw_command_supported
   provider_transport
   provider_owner
   adapter wiring
   readiness probe ID
   ```
11. Создать immutable `ProviderMountRegistry` с ровно 20 V2 entries. API:
   ```python
   class ProviderMountRegistry(Protocol):
       def require_v2(self, action_id: str) -> ProviderMountSnapshotV2: ...
       def assert_current(self, snapshot: ProviderMountSnapshotV2) -> None: ...
       def snapshots(self) -> tuple[ProviderMountSnapshotV2, ...]: ...
   ```
   Lookup любого V1 action ID обязан возвращать `not_v2_action`, а не синтезировать mount spec.
12. Создать `V2ActionSchemaBinding` и ровно 20 строковых bindings из §2.4,
    а также `V2ActionSemanticBinding` и ровно 20 rows из §2.5. Descriptor
    construction выполняет exact join двух матриц; adapter code не дублирует
    security semantics. `pth` resolves to `pass_the_hash` before dispatch.
13. Начальное состояние каждой V2 identity:
    ```text
    configured=true
    mounted=false
    typed_action_supported=true
    raw_command_supported=false
    ```
14. `ToolDef.enabled` оставить только raw facade state.
15. Raw names всех 20 возвращают `typed_action_required`.
16. Перенести manual identity declarations из `core/tools/quarantined.py` в новый `core/tools/manual_actions.py`.
17. `core/tools/quarantined.py` временно оставить compatibility re-export.
18. `scripts/quality/provider_legacy_field_inventory.py` должен AST-анализом классифицировать consumers:
    ```text
    V1-only descriptor.provider/provider_mounted reads
    V2/shared runtime reads
    constructor keywords
    serialization keys
    docs/tests assertions
    ```
19. Не выполнять глобальную замену всех `descriptor.provider`/`descriptor.provider_mounted` на registry lookup.
20. Миграция runtime consumers:
    ```python
    match catalog.resolve_entry(action_id):
        case LegacyActionCatalogEntry(descriptor=legacy):
            provider_owner = legacy.provider
            mounted = legacy.provider_mounted
        case TypedActionCatalogEntry(descriptor=typed):
            mount = mount_registry.require_v2(typed.action_id)
            spec = mount.spec
            provider_owner = spec.provider_owner
            mounted = spec.mounted
    ```
21. V1 construction/serialization:
    ```text
    96 existing adapters сохраняют current descriptor constructor и V1 serialized schema
    ProviderMountRegistry для них не вызывается
    ```
22. V2 construction/serialization:
    ```text
    20 typed adapters создают ActionDescriptorV2
    provider/provider_mounted constructor keywords запрещены
    V2 descriptor snapshot не публикует provider/provider_mounted
    V2 mount snapshot публикует provider_owner/mounted
    ```
23. Explicit V1→V2 migration decoder:
    ```text
    читает V1 schema
    не переносит provider/provider_mounted как V2 authority
    разрешает V2 ProviderMountSpec только по action_id
    отклоняет action_id, которого нет в 20-entry V2 registry
    ```
24. AST gate:
    ```text
    legacy fields запрещены во всех V2 modules и shared V2 authorization/readiness paths
    V1 allowlist разрешён только для adapter_api_version=1 compatibility modules
    новый V1 consumer запрещён без обновления reviewed allowlist
    ```
25. Ratchet:
    ```text
    V2-path legacy field consumer count == 0
    V1 allowlist не увеличивается
    V1 allowlist сокращается только при отдельной миграции V1 adapter в V2
    unmounted V2 count не увеличивается
    ```
26. Добавить collision checks:
    ```text
    action ID
    display name
    aliases
    adapter owner
    provider owner for V2
    ```
27. Обновить package exports/import smoke для нового `manual_actions.py`.
28. `quality/provider-mounts.json` является только `GENERATE` output; у него нет `CREATE` owner и ручное редактирование запрещено.
29. `scripts/quality/provider_plan_ledger_gate.py` parses this checked-in plan,
    supports only exact `CREATE`/`MODIFY`/`DELETE`/`GENERATE` headings, expands
    the single reviewed generated-lock brace grammar before validation and rejects duplicate create, modify-before-
    create, create-existing and ambiguous prose entries.
30. The parser recognizes exactly `@PR20_GENERATED_CREATE_PATHS@` and
    `@PR20_GENERATED_MODIFY_PATHS@` as zero-path sentinels only when each is the
    final nonblank line of the matching PR-20 CREATE/MODIFY fence. They never
    enter ownership/existence sets. Any other `@...@`, wrong PR/fence/order,
    duplicate, or path after a sentinel fails. `validate --phase=planning`
    permits both; `validate --phase=final` rejects either.
## Acceptance

```text
ровно 20 ProviderMountSpec entries, только для V2 identities
96 V1 adapters продолжают разрешаться без ProviderMountRegistry
ActionCatalog возвращает tagged LegacyActionCatalogEntry | TypedActionCatalogEntry
TypedActionCatalogEntry использует PR-1 TypedActionAdapterRegistrationV2, а не future PR-7 protocol
ProviderMountRegistry отклоняет V1 action IDs
ActionDescriptorV2 не содержит provider или provider_mounted
ProviderMountSpec не содержит manual_gate или execution_node_kind
существующий V1 ActionKind enum остаётся неизменным
ExecutionNodeKind является отдельным enum
V2 runtime не читает legacy descriptor.provider/descriptor.provider_mounted
V1 compatibility path не требует V2 mount spec
LegacyActionDescriptorV1 сохраняет существующий schema_version default и constructor compatibility
ActionDescriptorV2 использует exact input_schema_id/result_schema_id из §2.4 без импортов PR-6/PR-7 DTO
schema binding matrix содержит ровно 20 immutable rows и не содержит type objects
semantic binding matrix содержит ровно 20 rows и владеет aliases/kind/node/capability/risk/facts/stage/manual/check/verify
unknown required_fact_type_id makes catalog invalid when PR-4 registry is installed
нет ActionDescriptorV2(provider=...) или ActionDescriptorV2(provider_mounted=...)
legacy V1→V2 decoder отбрасывает owner/mount authority
quality/provider-mounts.json существует только как generated snapshot
manual_actions.py существует и является canonical manual identity module
quarantined.py только re-export
manifest/catalog/registry согласованы
raw dispatch возвращает typed_action_required
```

## Тесты

```text
test_provider_mount_registry_has_20_v2_entries
test_catalog_resolves_96_legacy_and_20_typed_entries
test_catalog_entry_union_is_exhaustive
test_typed_catalog_entry_uses_registration_protocol_available_in_pr1
test_registry_rejects_v1_action_id
test_v1_provider_fields_remain_inside_v1_path
test_v1_path_does_not_query_provider_mount_registry
test_v2_path_never_reads_legacy_provider_fields
test_descriptor_v2_has_no_provider_or_provider_mounted_fields
test_descriptor_v2_owns_check_and_verify_policy
test_final_20_check_verify_policy_matrix_exact
test_provider_mount_spec_has_no_manual_gate_or_execution_node_kind
test_existing_action_kind_enum_unchanged
test_execution_node_kind_is_separate
test_v1_schema_version_default_and_constructor_are_preserved
test_action_adapter_v1_is_alias_of_existing_action_adapter
test_descriptor_v2_uses_schema_ids_without_pr6_pr7_imports
test_v2_schema_binding_matrix_has_exact_20_rows
test_v2_schema_binding_ids_match_normative_table
test_descriptor_schema_ids_match_binding_matrix
test_v2_semantic_binding_matrix_has_exact_20_rows
test_descriptor_semantics_match_binding_matrix
test_pth_alias_resolves_to_pass_the_hash_before_dispatch
test_alias_collision_across_v1_v2_is_denied
test_provider_plan_ledger_has_single_create_owner
test_no_schema_v2_provider_constructor_keywords
test_v1_to_v2_decoder_discards_legacy_wiring_authority
test_provider_legacy_field_inventory_matches_reviewed_v1_allowlist
test_generated_manifest_has_no_create_owner
test_manual_actions_file_is_canonical_owner
test_quarantined_is_compatibility_reexport
test_manifest_snapshot_matches_runtime_registry
test_raw_tool_state_is_independent
test_unmounted_ratchet_never_increases
test_aliases_have_single_canonical_owner
```

---

# PR-2. Authenticated ingress invocation lease и atomic approval budget

## Цель

Привязать V2 execution к реально аутентифицированному ingress invocation и определить атомарное расходование approval для concrete/root/router child attempts.

## CREATE

```text
core/auth/types.py
core/auth/ingress.py
core/auth/ingress_context.py
core/auth/ingress_store.py
core/auth/ingress_leases.py
core/auth/principals.py
core/auth/missions.py
core/auth/approvals.py
core/auth/approval_store.py
core/auth/approval_leases.py
core/auth/execution_graphs.py
core/actions/policy_snapshots.py
core/actions/canonical_state.py
core/actions/cancellation.py
core/actions/composite_execution.py
core/actions/child_execution.py
core/actions/request_v2.py
core/actions/typed_input_decoders.py
core/actions/execution_results_v2.py
core/actions/execution_budget.py
core/cli/auth_session.py
tests/test_action_request_v2_decoder.py
tests/test_execution_results_v2_foundation.py
tests/test_typed_input_decoder_registry.py
tests/test_execution_budget.py
tests/test_cancellation_controller.py
tests/test_child_execution_budget.py
tests/test_v2_executor_api.py
tests/test_child_execution_bridge.py
tests/test_ingress_invocation_lease.py
tests/test_ingress_channel_binding.py
tests/test_principal_authorization.py
tests/test_mission_authorization.py
tests/test_approval_authorization.py
tests/test_approval_execution_lease.py
tests/test_router_approval_consumption.py
```

## MODIFY

```text
core/actions/executor.py
core/actions/cancellation.py
core/actions/base.py
core/actions/models.py
core/execution/models.py
core/execution/policy.py
core/killchain/policy.py
core/cli/main.py
core/cli/application.py
core/ai/runtime.py
tests/test_action_input_executor_coverage.py
tests/test_execution_policy.py
tests/test_high_risk_action_contracts.py
tests/test_killchain_policy_coverage.py
tests/test_killchain_config_policy.py
```

## Реализация

1. Удалить из user-decoded V2 request:
   ```text
   ingress_session_ref
   principal_ref
   subject_id
   role
   approved
   approval_id authority fields
   parent_execution_id
   execution_graph_id
   execution budget
   ```
2. Реализовать `ActionRequestV2EnvelopeDecoder`, `BoundedTypedInputPayloadV2` и `BoundedActionRequestV2Envelope` в `core/actions/request_v2.py` с exact top-level schema, size/depth/string/item limits, unknown-field rejection and private canonical bytes. PR-2 не определяет `ActionRequestV2` и не импортирует `V2InputUnion`.
3. Реализовать fail-closed bootstrap `TypedInputDecoderRegistry.require_decoder(...) -> NoReturn` в `core/actions/typed_input_decoders.py`. До PR-6 decoder registrations отсутствуют, поэтому provider request не создаётся и V2 adapter не вызывается.
4. Создать в `core/actions/execution_results_v2.py` exact PR-2 foundation DTO из §4.0: `ExecutionStatusV2`, `CleanupStatusV2`, `CleanupErrorSummaryV2`, `CleanupSummaryV2`, `ExecutionResultV2`, `ActionExecutionReportV2`, включая exact `finalization_persistence_pending: bool`.
5. Создать `ActionPolicyRequestHeaderV2` в `core/actions/policy_snapshots.py`; PR-2 не импортирует PR-4 target/fact/reference DTO and does not define the final `ActionPolicyRequestSnapshot`.
6. Создать `CanonicalActionStaticState` в новом `core/actions/canonical_state.py`; PR-3 later modifies this file to add readiness-bearing `CanonicalActionState`.
7. Реализовать root-only PR-2 signatures из §4.8A. `_run_v2_internal` принимает только `BoundedActionRequestV2Envelope + RootExecutionBridge`; child overload добавляет PR-6 после появления `ActionRequestV2`.
8. Реализовать executor-owned `ExecutionBudget`, `ExecutionLineage`, `ExecutorCancellationController` and private concrete token in `core/actions/execution_budget.py` / `core/actions/cancellation.py`.
7. Добавить `IngressInvocationLease` из архитектурного раздела 4.
8. Lease создаётся только после reviewed ingress authentication.
9. Bind lease через `ContextVar`/internal executor API, не через payload.
10. `IngressSessionStore.resolve_invocation_lease()` атомарно проверяет:
   ```text
   session/principal revisions
   request ID
   peer identity
   transport instance
   channel binding
   nonce
   expiry/revocation/single-use
   ```
11. Executor выводит principal только из validated lease.
12. CLI login/session manager создаёт lease для каждого entered command.
13. HTTP/API middleware создаёт lease для каждого authenticated request.
14. C2 control ingress создаёт lease только после server-side `SO_PEERCRED` client authentication + operator API-key authentication.
15. Определить в PR-2 только exact `ChildIngressLease`, `RootExecutionBridge`,
    `ChildExecutionBridge` and private `RootExecutionAuthorityBundleV2` from
    §4.8A. `ExecutionBridge` и `V2ExecutionSource` не объявлять до PR-6.
16. Оставить ровно один public root `run_v2(...)` и один root-only internal `_run_v2_internal(...)`; child overload, aliases и router call появляются только в PR-6.
17. `ChildExecutionBridge` наследует cancellation token и только сужает deadline/output/depth budget.
18. Добавить `MissionAuthorizationSnapshot`.
19. Добавить `ApprovalAuthorizationSnapshot` и graph grants.
20. Добавить durable `ApprovalExecutionLease`.
21. Root concrete action:
    ```text
    reserve_attempt() → PENDING
    final readiness recheck
    release_before_start() on unavailable/race
    start() immediately before provider side effect
    ```
22. Root router/composite:
    ```text
    open execution graph
    authorize_router_step()
    consume zero uses
    ```
23. Selected concrete child:
    ```text
    reserve_attempt using same approval graph/budget
    max_uses checked against consumed + pending
    final readiness recheck
    start exactly one use at attempt start
    ```
24. Pre-start deny/unavailable/race releases pending reservation.
25. Post-`STARTED` failure/timeout/cancellation does not refund.
26. Nested routers reuse same graph.
27. No active fallback after `STARTED`.
28. Parent and child action/stage/operation/targets must both be approved.
29. Add `ExecutionPolicy.authorize_coarse(...)` and `authorize_deep(...)`; keep `authorize_registered` only for raw facade.
30. Unknown/disabled kill-chain stage denies parent and child separately.
31. Decision trace stores only refs/revisions/digests, budget summary and attempt state.
## Acceptance

```text
principal cannot be supplied or selected by caller
a copied ingress session ref is insufficient
ingress lease is bound to current authenticated peer/channel/request
lease is single-use
router child inherits verified ingress, not a new caller identity
manual gate requires OPERATOR principal + active mission + active approval
V2 envelope decoder accepts only bounded serialized envelope
PR-2 contains no ActionRequestV2 or V2InputUnion import
BoundedActionRequestV2Envelope is frozen and contains only bounded caller fields/private typed-input bytes
ActionExecutionReportV2 and ExecutionResultV2 are concrete mypy-visible PR-2 DTOs
typed input decoder registry fails closed until action-specific decoder is registered
execution budget/lineage are executor-owned and non-serializable
max_uses=1 parent router consumes zero
max_uses=1 selected child reserves before final readiness and consumes exactly one only on start
failed final readiness releases PENDING reservation without consuming use
concurrent children cannot oversubscribe approval
```

## Тесты

```text
test_v2_envelope_exact_schema
test_v2_envelope_rejects_unknown_authority_fields
test_v2_envelope_size_depth_and_item_limits
test_bounded_action_request_v2_envelope_is_frozen
test_bounded_envelope_exact_fields
test_pr2_has_no_action_request_v2_or_v2_input_union_import
test_execution_result_v2_foundation_exact_fields
test_action_execution_report_v2_foundation_exact_fields
test_action_execution_report_v2_has_finalization_persistence_pending
test_finalization_pending_requires_none_ref_and_durable_retry
test_finalization_not_pending_requires_durable_ref
test_pr2_policy_snapshot_contains_header_only
test_pr2_canonical_state_contains_static_state_only
test_executor_cancellation_controller_is_only_token_source
test_caller_cannot_construct_or_inject_cancellation_token
test_committed_result_has_no_cleanup_field
test_typed_input_decoder_registry_unknown_action_denied
test_typed_input_decoder_registry_never_returns_dict_or_any
test_execution_budget_not_decodable_from_request
test_child_budget_can_only_shrink
test_v2_requires_current_ingress_invocation_lease
test_ingress_lease_not_decodable_from_request
test_forged_lease_object_denied
test_copied_session_ref_without_current_channel_denied
test_stale_lease_denied
test_consumed_lease_denied
test_revoked_session_denied
test_peer_uid_gid_pid_mismatch_denied
test_transport_instance_mismatch_denied
test_channel_binding_mismatch_denied
test_request_id_binding_mismatch_denied
test_principal_ref_cannot_be_supplied_by_request
test_principal_must_match_ingress_session
test_child_ingress_lease_derived_by_executor_only
test_v2_has_one_public_root_and_one_internal_execution_api
test_pr2_internal_api_accepts_only_root_bridge_and_bounded_envelope
test_child_overload_is_absent_before_pr6
test_execution_bridge_alias_is_absent_before_pr6
test_v2_execution_source_alias_is_absent_before_pr6
test_child_ingress_lease_exact_fields_and_single_use
test_router_calls_only_run_v2_internal

test_missing_inactive_cross_mission_denials
test_manual_gate_requires_operator_principal
test_approval_action_capability_stage_operation_target_bindings

test_concrete_root_consumes_one_use
test_router_parent_consumes_zero_uses
test_nested_router_consumes_zero_additional_uses
test_selected_child_reserves_before_final_readiness
test_selected_child_consumes_one_use_only_on_start
test_final_readiness_failure_releases_pending_reservation
test_pre_attempt_failure_releases_pending_reservation
test_attempt_failure_keeps_consumed_use
test_two_children_race_max_uses_one_exactly_one_wins
test_child_cannot_mint_independent_budget
test_root_authority_bundle_is_private_and_binds_budget_to_single_controller
test_root_and_child_internal_overloads_supply_exact_execution_creation_authority
test_no_active_fallback_after_attempt_start
```

---

# PR-3. Dynamic readiness subsystem и immediate pre-call recheck

## Цель

Отделить provider environment readiness от request-specific resources и гарантировать recheck прямо перед invocation.

## CREATE

```text
core/actions/readiness.py
core/actions/readiness_registry.py
core/actions/readiness_probes.py
core/cli/doctor.py
tests/test_provider_readiness.py
tests/test_provider_readiness_recheck.py
tests/test_provider_doctor.py
tests/test_dependency_readiness.py
tests/test_canonical_action_state.py
```

## MODIFY

```text
core/actions/executor.py
core/actions/provider_mounts.py
core/actions/canonical_state.py
core/cli/main.py
config.py
config.yaml
```

## Реализация

PR-3 is independently type-checkable and does not import/call the future
`ActionRequestV2`, `check_bound`, phase-lease controller or typed adapter.
Steps 4–10 define readiness snapshots, comparison helpers and dormant
executor-hook contracts typed only with PR-2/PR-3 owners; their helper tests
exercise ordering state without invoking a provider. PR-7, after PR-5/PR-6
types exist, performs the single final executor wiring of the numbered
lifecycle in §4.

1. Add exact `DependencyKindV2`, `DependencyStateV2`, `DependencyReadiness` and `ProviderReadinessSnapshot`; modify the PR-2 `core/actions/canonical_state.py` only to add `CanonicalActionState` that composes the existing `CanonicalActionStaticState`:
   ```text
   probe_version
   provider_generation
   checked_at
   expires_at
   dependency states
   reason codes
   ```
2. Реализовать:
   ```text
   PythonImportProbe
   BinaryProbe
   PlatformProbe
   DaemonProtocolProbe
   CompositeLeafProbe
   ```
3. Добавить TTL cache.
4. Initial probe выполняется только после successful `authorize_coarse(...)` и до `authorize_deep(...)`.
5. После atomic snapshot/reference checkout and successful `check_bound` branch
   on `ExecutionNodeKind`.
6. `LEAF`: reserve `attempt_lease=PENDING`; perform a fresh full recheck; create
   the PENDING phase controller, open executor material, bind views; revalidate
   checkout and call `readiness_registry.assert_current(fresh_readiness)`
   immediately before `attempt_lease.start()`. Approval use is charged only by
   the atomic PENDING→STARTED transition.
7. `COMPOSITE_ROUTER`: reserve no attempt and open no material. Perform a fresh
   full recheck after check, compare action/mount/probe/provider/daemon/dependency
   identity and generation, call `checkout_bundle.assert_current()`, then
   `authorize_router_step()` immediately before
   `invoke_route()`. Unavailable returns before any child selection.
8. Recheck сравнивает:
   ```text
   action ID
   provider ID
   mount revision
   mount digest
   probe version
   provider generation
   daemon instance ID
   dependency state
   expiry
   snapshot digest recomputed from the full canonical body
   ```
9. Если LEAF recheck стал unavailable:
   ```text
   attempt_lease.release_before_start()
   provider attempt не STARTED
   approval use не расходуется
   checkout закрывается
   invocation finally выполняется
   ```
10. Если LEAF recheck successful:
   ```text
   controller = _ProviderExecutePhaseLeaseControllerV2()
   opened_bundle = checkout_coordinator.open_materials(checkout_bundle)
   material_bundle = material_binder.bind(
       opened_bundle,
       controller.view,
       _phase_controller=controller,
   )
   checkout_bundle.assert_current()
   readiness_registry.assert_current(fresh_readiness)
   attempt_lease.start()
   provider boundary activates controller and invokes
   ```
11. Не включать конкретные refs/target service facts в readiness.
12. `doctor --providers` показывает configured/mounted/available отдельно.

## Acceptance

```text
available отсутствует в manifest
missing session/route не является readiness failure
readiness может измениться между policy и invocation
reserve_attempt происходит до final readiness recheck
failed final recheck освобождает PENDING lease без списания use
provider не вызывается после failed pre-call recheck
router performs a fresh identity/generation recheck without attempt/material
post-open generation race is detected immediately before LEAF start
```

## Тесты

```text
test_readiness_is_dynamic
test_readiness_cache_expires
test_missing_request_resource_is_not_readiness_failure
test_missing_binary_is_readiness_failure
test_composite_readiness_from_leafs
test_pre_call_recheck_runs_after_checkout
test_attempt_reservation_precedes_final_readiness_recheck
test_pre_call_recheck_detects_generation_change
test_pre_call_recheck_unavailable_prevents_attempt_start
test_pre_call_recheck_closes_checkout
test_pre_call_recheck_releases_pending_attempt_lease_without_use
test_router_rechecks_after_check_without_attempt_or_material
test_router_generation_change_prevents_child_selection
test_router_fact_or_reference_revision_change_during_check_prevents_selection
test_post_open_generation_change_closes_material_and_preserves_approval_use
test_doctor_does_not_print_authorized_without_request
```

---

# PR-4. Trusted facts, target extraction и atomic ingress/reference checkout

## Цель

Сделать ingress/principal/fact/reference/target resolution executor-owned и гарантировать, что material раскрывается только внутри atomic checkout после всех revision/ACL checks.

## CREATE

```text
core/actions/reference_snapshots.py
core/actions/reference_authorization.py
core/actions/reference_types.py
core/actions/sensitive_integrity.py
core/actions/reference_resolvers.py
core/actions/reference_checkout.py
core/actions/checkout_models.py
core/actions/materials.py
core/actions/target_extraction.py
core/actions/target_scope.py
core/actions/trusted_facts.py
core/actions/action_preconditions.py
core/sessions.py
core/artifacts.py
core/pivot_routes.py
core/c2/resources.py
tests/test_reference_snapshots.py
tests/test_reference_authorization.py
tests/test_reference_state_types.py
tests/test_bound_material_wrappers.py
tests/test_reference_checkout.py
tests/test_checkout_models.py
tests/test_bound_material_bundle.py
tests/test_ingress_checkout.py
tests/test_target_extraction.py
tests/test_target_scope_policy.py
tests/test_trusted_fact_decoder.py
tests/test_action_precondition_registry_v2.py
tests/test_policy_request_snapshot_v2.py
```

## MODIFY

```text
core/auth/ingress_store.py
core/auth/principals.py
core/auth/missions.py
core/auth/approval_leases.py
core/auth/approvals.py
core/auth/approval_store.py
core/execution/models.py
core/execution/policy.py
core/actions/policy_snapshots.py
core/actions/executor.py
core/actions/models.py
core/credentials.py
core/secrets.py
core/ai/fact_store.py
core/ai/fact_predicates.py
tests/test_credential_reference_boundary.py
tests/test_credentials_access_contracts.py
tests/test_scope_indirection_contracts.py
tests/test_execution_gate.py
```

## Реализация

1. V2 request принимает только opaque refs:
   ```text
   mission_ref
   approval_ref
   precondition_fact_refs
   resource refs в typed input
   ```
2. Ingress handle передаётся executor отдельно.
3. Добавить closed `TrustedFactSnapshot` и `TrustedFactDecoder` с exact
   `TrustedFactTrustLevelV2` / `FactFreshnessStatus` /
   `EvidenceCoverageStatus`; every `UNKNOWN` value blocks a precondition.
4. Modify the existing PR-2 `core/actions/policy_snapshots.py` and add the final
   `ActionPolicyRequestSnapshot` that composes `ActionPolicyRequestHeaderV2`
   with PR-4 targets/principal/mission/approval/facts/references.
5. Добавить exact `ReferenceMetadataSnapshot` closed union. The dependency-free
   `SensitiveIntegrityTagV2` is owned here in PR-4; PR-5 imports it for buffers
   and authenticators and never redeclares it:
   ```text
   CredentialReferenceSnapshot
   SessionReferenceSnapshot
   NonSensitiveArtifactReferenceSnapshot
   SensitiveArtifactReferenceSnapshot
   PivotRouteReferenceSnapshot
   C2ReferenceSnapshot
   DeploymentReferenceSnapshot
   ```
5. Добавить `ReferenceAuthorizationSnapshot`.
6. Обязательный invariant:
   ```text
   metadata.reference == authorization.reference
   ```
7. Добавить:
   ```text
   metadata revision
   authorization revision
   mission binding
   owner subject
   permitted subjects/actions/capabilities
   authorization scope
   expiry/state
   ```
8. Реализовать:
   ```text
   Credential resolver поверх existing CredentialStore
   SessionStore
   ArtifactStore
   PivotRouteStore
   C2ResourceStore
   DeploymentStore metadata boundary
   ```
9. Добавить generic `ActionTargetExtractorRegistry` из §5.4 без import `V2InputUnion`; PR-4 ships with zero registrations and exact typed registrations appear in PR-6.
10. Создать `core/actions/reference_types.py` и exact enums `SessionState`, `ArtifactKind`, `RouteState`, `C2ResourceKind`, `C2ResourceState`, `DeploymentState`; normalize single `CredentialAuthKind` owner in `core/credentials.py`.
11. Определить executor-only checkout handles,
    `ExecutorOpenedMaterialV2`/bundle из §7.1A. Provider views and final
    `BoundMaterialBundle` are added only by PR-5 after the phase-lease and
    zeroizable types exist.
12. Реализовать в `core/actions/target_scope.py` единственные canonical `TargetRole`, `TargetKind`, `NetworkProtocol`, `ExtractedActionTarget`, `TargetScopeRule`, `TargetScopeSnapshot`, `TargetScopeCanonicalizer` и `TargetScopePolicy`.
13. Извлекать из typed DTO:
    ```text
    primary target
    destination host
    every SSH hop
    scan target
    callback/bind/listen endpoint
    resource-bound targets
    ```
14. V2 target extraction через command parsing запрещён.
15. Добавить единственный `IngressSessionCheckoutRequest`; сокращённый alias запрещён.
16. Добавить store-level atomic `checkout()`.
17. Добавить dormant `ReferenceCheckoutCoordinator.checkout_many()` helper;
    PR-5 later makes production access factory-token-private and wires the
    intent-bound checkout owner factory.
18. Coordinator включает:
    ```text
    ingress session
    ingress-derived principal
    mission
    approval execution lease
    facts
    resource metadata/ACL
    extracted targets
    ```
19. Coordinator использует canonical lock order.
20. `checkout_many()` не раскрывает material до успешной проверки всех participants.
21. `ReferenceCheckoutCoordinator.open_materials(checkout_bundle)` атомарно повторяет revisions, проверяет typed `TargetScopeSnapshot` через `TargetScopePolicy` и только затем раскрывает checkout-owned material; PR-4 не принимает будущий `InvocationScope` parameter.
22. После snapshot checkout and successful side-effect-free `check_bound`, но до
    material resolution, executor создаёт `PENDING` attempt reservation.
23. После reservation выполнить immediate readiness recheck. Только при available
    executor вызывает `checkout_coordinator.open_materials(checkout_bundle)`, повторяет `assert_current()` и затем
    выполняет `attempt_lease.start()`.
24. При failed recheck material не открывается:
    ```text
    attempt_lease.release_before_start()
    no provider attempt STARTED
    no approval use
    all materials/leases closed
    ```
25. Add `ActionPreconditionRegistryV2`, which binds every semantic-matrix
    `required_fact_type_id` to one exact `TrustedFactType` predicate. It rejects
    unknown IDs at catalog assembly and exposes no reference/resource-existence
    predicate; those remain typed checkout checks.

PR-4 likewise creates only checkout/material/precondition APIs and dormant
ordering helpers; steps 22–24 are contract pseudocode, not a PR-4 import of
future V2 adapter/request/phase types. Concrete check→reservation→recheck→open
material wiring belongs to PR-7's executor modification.
## Acceptance

```text
principal нельзя checkout-ить без ingress lease
metadata/reference/ACL identity invariant enforced
PR-4 ReferenceMetadataSnapshot is a closed seven-variant union; PR-15 adds the
eighth enrollment-specific variant
all reference state enums have exact values and one owner
PR-4 executor opened-material handles/bundle have exact private fields; final
tree has eight phase-leased bound material variants after PR-5/PR-15
PR-4 materials.py has no import from the future PR-5 InvocationScope
checkout request/bundle DTOs are exact and frozen
reference access mode is executor-derived and metadata-only refs never open material
IngressSessionCheckoutRequest is the only ingress checkout request name
AttemptLeaseState is one enum owned by core/auth/approval_leases.py
mission/approval/reference scopes use TargetScopeSnapshot, not tuple[str]
ReferenceStore.checkout accepts ExtractedActionTarget values
ExecutionPolicy delegates all V2 matching to TargetScopePolicy
every required_fact_type_id resolves exactly once; unknown IDs fail catalog
нет dict metadata
нет local path/live handle в snapshot
nested targets извлекает executor
material не раскрывается до successful checkout всех refs/facts/approval
fresh readiness выполняется после snapshot checkout/reservation и до material open; material открывается только после successful recheck и до atomic attempt start
```

## Тесты

```text
test_ingress_checkout_required
test_principal_checkout_requires_ingress_binding
test_snapshot_is_frozen
test_snapshot_is_json_safe
test_metadata_authorization_reference_match_required
test_owner_can_use_reference
test_permitted_subject_can_use_reference
test_other_subject_denied
test_other_mission_denied
test_scope_mismatch_denied
test_action_acl_mismatch_denied
test_capability_acl_mismatch_denied
test_metadata_revision_race_denied
test_acl_revision_race_denied
test_ingress_revision_race_denied
test_fact_revision_race_denied
test_trusted_fact_unknown_trust_fails_closed
test_trusted_fact_unknown_freshness_fails_closed
test_trusted_fact_unknown_coverage_fails_closed
test_semantic_matrix_required_fact_ids_resolve_exactly_once
test_reference_existence_is_not_a_string_fact_precondition
test_policy_request_snapshot_finalized_in_pr4
test_approval_lease_revision_race_denied
test_snapshot_never_contains_path_or_handle
test_reference_metadata_snapshot_union_is_exhaustive
test_reference_state_enums_exact_values_and_single_owner
test_bound_material_wrapper_union_is_exhaustive
test_each_bound_material_wrapper_has_exact_fields
test_bound_material_handle_fields_are_private_and_non_serializable
test_scoped_temp_artifact_handle_is_defined_and_checkout_bound
test_pr4_materials_has_no_future_invocation_scope_import
test_bundle_requires_one_checkout_id_and_unique_references
test_reference_access_mode_is_executor_derived
test_metadata_only_reference_never_opens_material
test_checkout_request_models_are_frozen_and_closed
test_short_alias_ingress_checkout_request_is_absent
test_executor_calls_reference_checkout_coordinator_open_materials_only_after_successful_final_readiness
test_bound_material_bundle_is_non_serializable
test_nested_hops_extracted
test_destination_target_extracted
test_bind_endpoint_extracted
test_target_role_values_are_closed_and_single_owner
test_network_protocol_values_are_closed_and_single_owner
test_target_kind_values_are_closed_and_single_owner
test_raw_command_not_used_for_v2_targets
test_multi_checkout_all_or_release
test_material_not_opened_on_partial_failure
test_final_readiness_runs_before_any_material_open
test_open_materials_revalidates_all_fences_atomically
test_failed_open_materials_returns_no_partial_bundle
test_executor_checkout_bundle_has_no_open_or_reveal_method
test_reference_checkout_coordinator_opens_material_only_after_successful_final_readiness
test_readiness_recheck_after_pending_reservation_before_start
test_failed_recheck_releases_reservation_closes_checkout_without_opening_material_and_preserves_use
```

---

# PR-5. Guaranteed `finally` cleanup, closed participants and transactional outcome commit

## Цель

Create the PR-safe transaction/staging foundation, guarantee cleanup on every
outcome, and make sensitive data, facts, credentials, artifacts, result,
audit/outbox and resources participants of one durable logical coordinator.

## CREATE

```text
core/actions/invocation_scope.py
core/actions/cleanup_operation_context.py
core/actions/execution_commit_types.py
core/actions/execution_commit.py
core/actions/execution_commit_store.py
core/actions/execution_recovery_types.py
core/actions/execution_creation_store.py
core/actions/cancellation_recovery.py
core/actions/execution_cancellation_service.py
core/actions/execution_no_return_admission.py
core/actions/participant_authority.py
core/actions/intent_bound_owner_factories.py
core/actions/execution_commit_participants.py
core/actions/provider_participants.py
core/actions/execution_finalization.py
core/actions/execution_reconciler.py
core/actions/managed_resources.py
core/actions/execution_drafts.py
core/actions/execution_result_store.py
core/actions/provider_results.py
core/actions/zeroizable_buffers.py
core/actions/sensitive_transactions.py
core/actions/provider_invocation.py
core/actions/provider_call_types.py
core/actions/provider_call_boundary.py
core/actions/provider_call_recovery.py
core/actions/finalization_retry.py
core/actions/sensitive_integrity_runtime.py
core/actions/sensitive_artifact_envelope.py
tests/test_invocation_cleanup.py
tests/test_provider_results_foundation.py
tests/test_zeroizable_buffers.py
tests/test_secret_value_v2.py
tests/test_bound_provider_invocation_context.py
tests/test_provider_call_boundary.py
tests/test_provider_call_type_ownership.py
tests/test_provider_call_boundary_timeout.py
tests/test_provider_call_boundary_cancellation.py
tests/test_provider_call_boundary_output_limit.py
tests/test_execution_commit_transaction.py
tests/test_execution_commit_type_ownership.py
tests/test_execution_commit_participant_protocol.py
tests/test_participant_registration_contract.py
tests/test_execution_visibility_finalization.py
tests/test_execution_result_store_v2.py
tests/test_execution_finalization.py
tests/test_sensitive_ingestion_transaction.py
tests/test_execution_commit_recovery.py
tests/test_execution_in_doubt_recovery.py
tests/test_managed_resource_lifecycle.py
tests/test_execution_recovery_type_ownership.py
tests/test_execution_creation_store.py
tests/test_cancellation_recovery.py
tests/test_execution_cancellation_service.py
tests/test_execution_no_return_admission.py
tests/test_participant_execution_authority.py
tests/test_execution_continuation_recovery.py
tests/test_intent_bound_owner_factories.py
tests/test_approval_leases.py
tests/test_execution_graphs.py
tests/test_provider_call_recovery.py
tests/test_detached_provider_call_claims.py
tests/test_execution_finalization_fences.py
tests/test_finalization_retry_reconciler.py
tests/test_sensitive_integrity_runtime.py
tests/test_sensitive_artifact_envelope.py
tests/test_sensitive_artifact_reservation_recovery.py
tests/test_cleanup_operation_context.py
```

## MODIFY

```text
core/actions/executor.py
core/actions/base.py
core/actions/models.py
core/actions/execution_results_v2.py
core/actions/materials.py
core/actions/reference_checkout.py
core/auth/approval_leases.py
core/auth/execution_graphs.py
core/execution/results.py
core/ai/sensitive_ingestor.py
core/ai/fact_store.py
core/credentials.py
core/secrets.py
core/sessions.py
core/artifacts.py
core/pivot_routes.py
core/c2/resources.py
tests/test_reference_checkout.py
tests/test_cancellation_controller.py
```

## Реализация

1. Add the exact idempotent LIFO `InvocationScope` and support types.
   `cleanup_operation_context.py` solely owns the bounded live/restart cleanup
   policy, subject, context and executor-owned authority; no cleanup consumer
   constructs a context or reuses a pre-restart token/deadline.
2. In `core/actions/zeroizable_buffers.py`, implement concrete
   `OwnedZeroizableSensitiveBufferV2`, `OwnedZeroizableSensitiveBufferLeaseV2`
   and `ZeroizableDestinationBufferV2`; the destination is an owned mutable
   capability, not a raw caller bytearray, and every `read_into()` call is
   enclosed by a mandatory `finally` that destroys destination and source lease.
   `core/actions/sensitive_integrity_runtime.py` owns the final persistent-keyring
   HMAC authenticator/stream; `sensitive_artifact_envelope.py` owns the streaming
   sealing writer. Both import the PR-4 tag DTO and reject custom authenticators.
3. In `core/secrets.py`, define the sole `SecretValue` protocol plus concrete
   `OpaqueSecretValueV2` and reviewed `LegacySecretValueAdapterV2`. PR-6 and
   PR-14 import them; no later PR redeclares the protocol or implementation.
4. Modify PR-4 `core/actions/materials.py` to add the phase-leased provider-view
   family, sensitive/non-sensitive artifact split, `ProviderMaterialBinderV2`
   and final `BoundMaterialBundle`; executor checkout handles remain private and
   cleanup-capable after provider-view revocation.
5. In `core/actions/provider_results.py` create only the PR-5 foundation:
   draft refs, `ProviderResultFoundationV2`, managed-resource kinds and the
   one-shot zeroizable sensitive capability. Concrete PR-7 result variants are
   not imported.
6. Add the PR-5-only stage requests, provider/internal participant payload
   unions, `ProviderParticipantRegistrationFacade`, restricted
   `ProviderInvocationScopeV2`, `ProviderExecutePhaseLeaseV2`, executor-internal
   `SensitiveBatchStagingCapabilityV2`, concrete
   `OwnedSensitiveObservationHandleV2`/factory and
   `BoundProviderInvocationContext` from §8.2/§8.9.
5. Add the exact `ExecutionCommitParticipant` protocol with
   `prepare/commit/finalize_visibility/rollback/reconcile` and the executor-owned
   registry/coordinator. Only the coordinator may invoke those methods.
6. Add dependency ordering through provider/internal registration specs.
   `execution_recovery_types.py` is the acyclic dependency-free owner of intent/
   coordinator/lease/call recovery refs, intent phase and finalization fence;
   commit, finalization and boundary modules import it. The coordinator
   topologically orders the phased prepare graph and shared commit/finalize graph and rejects
   cycles or unknown dependencies.
7. Add `ProviderCallBoundary.invoke_execute(...)` as the only PR-5 V2 execute
   boundary. It receives the single invocation context and enforces deadline,
   cancellation, subprocess group termination, network/IPC deadlines, output
   bounds and redacted exception conversion.
   `ExecutionCreationStore`, intent-bound inert owner factories, call recovery
   journal/detached store and finalization-retry reconciler are concrete PR-5
   services with the exact CAS/recovery contracts in §8; none is a later PR
   placeholder.
   `provider_call_types.py` is the dependency-free sole owner of
   `ProviderCallPhaseV2`, `ProviderPhaseCallPlanV2`, call-plan digest,
   and termination/run/closure outcome DTOs only. Dependency-light
   `ProviderCallRecoveryStateV2`/`ProviderCallRecoveryRefV2` are owned only by
   `execution_recovery_types.py` because the intent imports them;
   `provider_call_recovery.py` owns `ProviderCallRecoveryRecordV2`, every
   detached ref/draft/state/record and the journal/termination-store protocols.
   `provider_call_boundary.py` imports the DTO module and the recovery protocol
   one-way; recovery never imports the boundary implementation. No symbol is
   redeclared. Ownership/import-direction tests ratchet the split.
8. PR-5 must not import or annotate with:
   ```text
   V2InputUnion
   ActionRequestV2
   concrete ProviderResult variants
   C2ArtifactBuildOutput
   C2ArtifactStageRequestV1
   StagedC2Artifact
   AgentTaskEnvelopeV12
   enrollment PR-15/PR-16 models
   ```
   `execution_creation_store.py`, `cancellation_recovery.py` and
   `execution_cancellation_service.py` are the exact concrete owners of atomic
   creation, durable graph cancellation and authenticated cancellation ingress;
   no public cancellation-store creation method or second controller factory
   exists. `execution_no_return_admission.py` solely owns the durable
   cancellation-versus-commit admission store and its read-back/recovery logic;
   its dependency-light body/ref/receipt DTOs and canonical digest remain in
   `execution_recovery_types.py`. `execution_finalization.py` owns the continuation recovery store,
   while `intent_bound_owner_factories.py` solely owns the generic/specialized
   owner factory contracts and creation specs; checkout/scope/approval modules
   expose only token-gated implementation hooks and never import that module.
   while the light DTOs/digests remain in `execution_recovery_types.py`.
9. Wrap the authoritative V2 path in an outer `try/except/finally` without an
   early return.
10. Cleanup runs on success, exception, timeout, cancellation, normalization,
    readiness/checkout race, staging error, participant error and finalization
    error. Cleanup failures never mask the primary outcome.
11. Convert SensitiveObservationIngestor, SecretStore, CredentialStore,
    FactStore, ArtifactStore, ExecutionResultStore, Audit/Outbox and managed
    resources to transaction staging participants.
12. Normal lookup rejects records unless coordinator state is final
    `COMMITTED`. A participant hidden commit is not sufficient.
13. Implement durable coordinator states from §8.4, including
    `COMMIT_APPLIED` and `FINALIZING_VISIBILITY`.
14. `commit_all_hidden()` durably commits participants without exposing
    cross-process resources. `finalize_all_visibility()` is the only visibility
    finalizer. Final local `COMMITTED` is persisted only after exact finalize
    receipts.
15. `IN_DOUBT` is probe-only; after `COMMIT_DECIDED`, rollback is forbidden and
    recovery only rolls forward.
16. Approval use consumed at concrete attempt STARTED is never refunded.
17. Define exact `ExecutionCommitStateV2`, `ExecutionCommitRecordV2`, prepare
    failure/effect/in-doubt receipts, reconcile dispositions and the participant
    registry materialization API from §8.2. All reversible participants prepare
    before the optional terminal external effect; no prepare follows dispatch.
18. Staging recomputes actual content digest/size/count, atomically registers
    internal store/resource participants and never trusts provider metadata.
19. Provider phase lease is revoked in `ProviderCallBoundary.finally`; cached
    material/facades/scope fail after return and verify receives only read views.
20. `SecretStore.checkout_zeroizable()` is the sole V2 secret bridge and never
    calls legacy `reveal()`. Borrowed views are released before wiping.
21. `InvocationFinalizationStore.persist_or_enqueue()` returns the closed durable
    outcome; if both persistence and enqueue fail, no pending report is returned.
22. Add AST/import gates for V2 adapters/providers prohibiting direct stores,
    coordinator, C2 client and global service getters except reviewed backend
    modules.

## Acceptance

```text
PR-5 type-checks without PR-6/PR-7/C2 implementation DTO
CancellationToken, SecretValue and zeroizable-buffer protocols each have one production concrete implementation/controller/adapter
all read_into destinations are owned zeroizable capabilities and are destroyed in finally
provider-visible and internal participant payload unions are disjoint and closed
ProviderParticipantRegistrationFacade.register has one closed result union
no bare dual return of ParticipantRegistrationRefV2 vs ManagedResourceDraftRefV2
provider type surface has no participant lifecycle/coordinator method
ExecutionCommitCoordinator is sole prepare/commit/finalize/rollback/reconcile caller
participant dependency graph is acyclic and deterministic
BoundProviderInvocationContext transaction IDs match both restricted facades
finally executes for every provider outcome
sensitive/provisional records are invisible before final COMMITTED
cross-process commit is hidden until finalize receipt
local success/result ref is not published before cross-process finalize ACK
no claim of simultaneous cross-process ACID visibility
IN_DOUBT preserves fenced effects and never repeats start
external effect is the terminal prepare frontier
provider context exposes no private scope transfer/close or sensitive staging
custom sensitive-handle implementations are rejected
finalization persistence is either durable record or durable retry entry
```

## Тесты

```text
test_pr5_has_no_future_pr_type_imports
test_secret_value_created_in_pr5_before_pr6_dto_import
test_secret_value_has_one_canonical_owner
test_secret_value_single_use_lease_and_clear_contract
test_participant_registration_payload_union_is_exhaustive
test_participant_registration_result_union_is_exhaustive
test_register_returns_single_closed_result_contract
test_managed_registration_result_contains_registration_and_resource_draft
test_payload_result_variant_mismatch_denied
test_participant_dependency_cycle_denied
test_commit_coordinator_is_only_prepare_caller
test_commit_coordinator_is_only_finalize_caller
test_provider_context_has_no_full_commit_transaction
test_owned_zeroizable_buffer_overwrites_and_releases_storage
test_zeroizable_destination_destroyed_after_read_into_success
test_zeroizable_destination_destroyed_after_read_into_exception
test_source_lease_destroyed_after_read_into
test_opaque_secret_value_single_use_and_clear
test_legacy_secret_adapter_is_only_v2_secret_bridge
test_provider_cannot_call_participant_lifecycle_by_type
test_provider_call_boundary_is_only_v2_invocation_path
test_provider_call_boundary_enforces_absolute_monotonic_deadline
test_provider_call_boundary_propagates_cancellation
test_provider_call_boundary_kills_subprocess_group
test_provider_call_boundary_bounds_output
test_provider_call_boundary_closes_daemon_ipc_on_timeout
test_phase_controller_is_sole_lease_source
test_pending_phase_lease_denies_every_provider_capability
test_boundary_activates_the_same_bound_phase_lease_object
test_boundary_always_revokes_phase_lease
test_executor_checkout_cleanup_remains_usable_after_provider_view_revocation
test_provider_material_views_expose_no_close_clear_or_transfer
test_sensitive_artifact_view_has_no_read_bytes
test_cleanup_finally_on_success
test_cleanup_finally_on_provider_exception
test_cleanup_finally_on_timeout
test_cleanup_finally_on_cancellation
test_cleanup_failure_does_not_mask_primary_outcome
test_sensitive_stage_not_visible_before_commit
test_hidden_participant_commit_not_normally_visible
test_cross_process_finalize_ack_precedes_local_result_publication
test_finalization_write_failure_sets_persistence_pending_true
test_finalization_write_success_sets_persistence_pending_false
test_finalization_pending_report_contains_durable_retry_ref
test_crash_after_hidden_commit_rolls_forward_finalize
test_crash_after_remote_finalize_before_local_committed_rolls_forward
test_unknown_external_effect_enters_durable_in_doubt
test_in_doubt_never_rolls_back_or_restarts
test_consumed_approval_not_refunded_after_late_failure
test_execution_commit_state_enum_and_transition_table_are_closed
test_reversible_participants_prepare_before_terminal_external_effect
test_no_prepare_runs_after_external_dispatch
test_dispatch_journal_forces_in_doubt_after_crash_before_coordinator_cas
test_provider_payload_union_rejects_result_audit_secret_credential_fact
test_provider_registration_digest_is_coordinator_computed
test_staging_recomputes_observation_artifact_payload_size_and_digest
test_provider_context_has_no_sensitive_stage_method
test_custom_sensitive_handle_implementation_rejected
test_sensitive_handle_factory_binds_current_transaction_and_phase
test_cached_material_scope_staging_participant_and_factory_fail_after_execute
test_provider_scope_has_no_transfer_or_close
test_fake_resource_owner_cannot_escape_cleanup
test_v2_secret_checkout_never_calls_reveal
test_exported_view_released_before_zeroize
test_mutable_source_zeroed_after_transfer
test_finalization_persist_or_enqueue_is_durable
test_finalization_double_persistence_failure_returns_no_false_pending_report
test_v2_provider_import_boundary_forbids_direct_infrastructure
test_root_creation_creates_one_graph_cancellation_row_and_binding
test_child_creation_inherits_graph_cancellation_without_second_row
test_stale_active_cancellation_snapshot_cannot_resume
test_cancel_race_with_controller_bind_signals_or_denies_before_verify
test_controller_binding_is_unbound_in_every_finally
test_graph_completion_clears_bindings_and_fences_late_cancel
test_authenticated_cancel_is_mission_scoped_non_enumerating_and_idempotent
test_execution_creation_replay_returns_same_controller_binding
test_attempt_reservation_crash_before_attach_reclaims_inert_record
test_attempt_reservation_crash_after_attach_before_activate_recovers_pending
test_executor_never_calls_graph_reserve_attempt_or_checkout_many_directly
test_checkout_owner_reserve_attach_activate_closes_every_crash_gap
test_continuation_handoff_recovers_each_ordered_crash_gap
test_continuation_completion_replay_returns_same_receipt
test_cancelled_parent_waits_for_detached_or_in_doubt_child_containment
test_authority_revocation_waits_for_child_containment_before_parent_finalization
test_detached_claim_expiry_reclaim_and_fencing
test_detached_probe_and_quiescence_require_current_claim
test_detached_completion_binds_one_final_report
test_wrong_fence_operation_or_coordinator_state_is_rejected
test_coordinator_has_no_caller_supplied_long_lived_fence
test_reversible_and_terminal_prepare_outcomes_are_disjoint
test_finalization_retry_expired_claim_is_reclaimed_with_higher_fence
test_sensitive_artifact_reservation_crash_before_and_after_seal_reconciles
test_sensitive_artifact_direct_stage_and_backend_transfer_are_mutually_exclusive
test_sensitive_artifact_transfer_replay_and_registration_failure_cleanup
test_execution_recovery_modules_import_acyclically_and_have_single_symbol_owners
test_intent_publish_then_complete_crash_replays_same_completion_receipt
test_successful_no_external_effect_intent_skips_owners_fenced_to_result_committed
test_sensitive_integrity_factory_rejects_custom_keyring_lease_stream_or_authenticator
test_sensitive_integrity_one_shot_and_all_chunkings_match_golden_framing
test_sensitive_integrity_key_rotation_restart_and_constant_time_tamper_denial
test_sensitive_integrity_stream_under_or_over_expected_total_bytes_fails_and_zeroizes
test_execution_creation_and_intent_completion_digest_golden_and_tamper_vectors
test_participant_authority_factory_rejects_wrong_checkout_mission_subject_or_transaction
test_participant_authority_current_records_are_monotonic_descendants_of_issued_binding
test_begin_root_failure_injection_leaves_no_intent_ownership_cancellation_or_binding_row
test_finalization_retry_record_claim_completion_golden_tamper_and_stale_complete
test_sensitive_artifact_six_digest_domains_golden_and_single_field_tamper
test_sensitive_artifact_stale_open_and_sealed_revision_cas_denied
test_cancel_wins_before_no_return_admission_aborts
test_no_effect_admission_wins_before_cancel_forces_roll_forward
test_effect_dispatch_admission_then_cancel_returns_dispatch_already_admitted
test_effect_dispatch_admission_then_failed_no_effect_can_abort
test_effect_dispatch_admission_then_confirmed_forces_roll_forward
test_crash_after_admission_before_coordinator_decision_recovers_receipt
test_no_return_admission_conflicting_transaction_effect_or_decision_replay_denied
test_cleanup_operation_context_cannot_be_caller_constructed_or_forged
test_cleanup_recovery_mints_fresh_bounded_deadline_and_controller_after_restart
test_expired_or_over_budget_cleanup_context_fails_before_handler_io
test_intent_bound_attempt_factory_exact_reserve_and_activate_signatures_typecheck
```

---

# PR-6. Closed V2 DTO, operation catalogs, agent-task schemas и target schemas

## Цель

Зафиксировать закрытые typed inputs для всех 20 identities, подготовить schema-compatible migration текущего raw-command agent wire и обеспечить единый executor-owned target extraction.

## CREATE

```text
core/actions/operation_catalog.py
core/actions/input_migrations.py
core/actions/target_schemas.py
core/c2/agent_task_models.py
core/c2/agent_task_protocol.py
core/c2/agent_task_compat.py
core/c2/task_catalog.py
core/c2/transport_catalog.py
core/c2/deployment_profiles.py
core/c2/resource_types.py
core/c2/build_models.py
core/c2/rebind_models.py
tests/test_operation_catalogs.py
tests/test_input_contracts_v2.py
tests/test_action_request_v2_model.py
tests/test_typed_input_decoder_registry_v2_contracts.py
tests/test_target_schemas.py
tests/test_canonical_supporting_types.py
tests/test_agent_task_protocol_models.py
tests/test_c2_build_models.py
tests/test_c2_artifact_stage_request.py
tests/test_enrollment_bounds_config.py
scripts/quality/dependency_lock_impact_gate.py
tests/test_dependency_lock_impact_matrix.py
```

## MODIFY

```text
core/actions/input_contracts.py
core/actions/request_v2.py
core/actions/typed_input_decoders.py
core/actions/provider_invocation.py
core/actions/child_execution.py
core/actions/target_extraction.py
core/actions/executor.py
tests/test_v2_executor_api.py
core/actions/adapters_c2.py
core/actions/adapters_pivot.py
core/actions/adapters_evasion.py
core/actions/adapters_kerberos.py
core/actions/adapters_ad_lateral.py
core/actions/adapters_ad_credential.py
core/plugins/schema.py
core/c2/protocol.py
core/runtime_config.py
config.py
config.yaml
.env.example
pyproject.toml
requirements/runtime.txt
requirements/locks/manifest.json
requirements/locks/linux-x86_64/cp310/{runtime,c2,reporting,osint-browser,test,mysql,external-tools,platform,full}.txt
requirements/locks/linux-x86_64/cp311/{runtime,c2,reporting,osint-browser,test,mysql,external-tools,platform,full}.txt
requirements/locks/linux-x86_64/cp312/{runtime,c2,reporting,osint-browser,test,mysql,external-tools,platform,full}.txt
```

## Реализация

1. Import `TargetRole`, `TargetKind` and `NetworkProtocol` only from PR-4 `core/actions/target_scope.py`; define the single owners and exact values of `RemoteExecService`, `C2DeploymentProfileId`, `C2DeploymentMethod`, `C2TargetOS`, `C2TargetArch`, `DNSRecordType`, `C2Transport`, `C2TransportConfig` and `C2CleanupReason` in the modules from §10.0; add redefinition architecture tests.
2. Добавить canonical frozen DTO из раздела 10:
   ```text
   PayloadKeyingInputV2
   KerberosExtractInputV2
   KerberosCrackInputV2
   PassTheTicketInputV2
   PassTheHashInputV2
   CredentialDumpInputV2
   RemoteExecInputV2
   RemoteForwardInputV2
   SSHChainHopInputV2
   SSHChainInputV2
   PivotProxyScanInputV2
   C2EnrollmentIssueInput
   C2TaskInputV2
   C2DeployInputV3
   DNSC2ChannelInputV2
   C2ChannelCreateInputV2
   C2CleanupInputV2
   ```
3. После объявления всех top-level DTO определить единственный `V2InputUnion` и frozen `ActionRequestV2` из §10.14A.
4. Только в PR-6 определить `V2ExecutionSource = BoundedActionRequestV2Envelope | ActionRequestV2` и `ExecutionBridge = RootExecutionBridge | ChildExecutionBridge`, затем modify the existing single `_run_v2_internal` method with root/child overloads from §4.8A.
5. Child overload до любого другого processing выполняет exact action/request/lease/lineage equalities из §4.8A.
6. Зарегистрировать в `TypedInputDecoderRegistry` ровно один exact decoder для каждого `ActionDescriptorV2.input_schema_id`; registry валидирует точную пару `(action_id, input_schema_id)` и fail closed при неизвестном schema ID, повторной регистрации или несовпадении action/schema.
5. Каждый decoder:
   ```text
   принимает только private bounded typed_input payload из ActionRequestV2EnvelopeDecoder
   отклоняет unknown fields и wrong variants
   возвращает closed V2InputUnion
   не принимает caller-created dataclass instance
   ```
6. `C2CleanupInputV2` принимает только:
   ```python
   resource_ref: str
   reason: C2CleanupReason
   ```
   `resource_kind`, lifecycle owner и cleanup backend разрешаются executor/store из canonical resource snapshot. Caller не выбирает backend.
7. `C2DeployInputV3` обязательно содержит:
   ```text
   enrollment_ref
   channel_ref
   access_session_ref
   source
   profile_id
   method
   ```
8. `C2DeploymentSource` является closed union:
   ```text
   PrebuiltArtifactSource
   BuildTemplateSource
   ```
9. Add exact `C2ArtifactBuildRequest`, `C2ArtifactBuildBinding` and `C2ArtifactRebindingRequest` from §10.7–§10.8: the binding contains the preallocated `deployment_ref`; plaintext token, local path and self-referential digest are absent.
10. Define the sole owner `C2TaskOperationId` in `core/c2/task_catalog.py`; add the four exact control-plane payload DTOs and their closed tagged union; add exact decoder bounds and operation/payload variant matching.
11. В PR-6 добавить только registration/capability models и module scaffold:
   ```text
   AgentRegistrationV12
   AgentCapabilitySetV12
   core/c2/agent_task_models.py без task/result wire DTO
   ```
   Канонические `AgentTaskEnvelopeV12`, `AgentTaskResultV12` и
   `AgentTaskDeliveryAckV12` добавляются ровно один раз в PR-15.
12. Зафиксировать правило:
    ```text
    C2TaskInputV2 — control-plane DTO
    PR-15 AgentTaskEnvelopeV12 — agent-wire DTO
    C2TaskCompiler — единственный converter между ними после PR-16; PR-6 не создаёт compiler и не тестирует его output
    ```
13. Не компилировать typed task в raw `command`.
14. В `agent_task_compat.py` разрешить только decoding legacy V11 rows/agents для migration inventory и drain; typed provider не вызывает этот compatibility encoder.
15. Добавить explicit schema/version constants:
    ```text
    C2_AGENT_PROTOCOL_V11 = "11.0"
    C2_AGENT_PROTOCOL_V12 = "12.0"
    C2_TASK_SCHEMA_V12 = "12.0"
    ```
16. Operation catalog компилирует enum ID только в provider/agent-owned closed operation descriptor, не в caller-supplied command string.
17. Запретить:
    ```text
    additional fields
    arbitrary command
    arbitrary output path
    channel_options dict
    deployment_profile dict
    task arguments dict
    caller-supplied cleanup resource kind/backend
    ```
18. Старые action DTO поддерживать только explicit one-way migration adapters.
19. Migration adapter:
    ```text
    никогда не превращает raw command в V2 operation автоматически
    возвращает migration_required для ambiguous legacy input
    ```
20. Для каждого canonical DTO зарегистрировать один `ActionTargetSchema`.
21. Target schemas извлекают:
    ```text
    primary target
    every SSH hop
    destination host
    proxy scan target
    callback/bind/listen endpoints
    reference-bound targets
    ```
22. Target schema не читает raw command, `parameters` или adapter invocation string.
23. Add exhaustive union checks through `typing_extensions.assert_never` for `C2TaskPayload` and `C2DeploymentSource`. Assert that `C2TransportConfig` is exactly `DNSChannelConfig` until a new concrete transport leaf is introduced, and that cleanup reasons are closed enums.
24. Add explicit runtime dependency `typing-extensions>=4.12`; import exhaustive helper only as `from typing_extensions import assert_never`. Regenerate cp310/cp311/cp312 runtime/test/full locks. Importing `assert_never` from stdlib `typing` is forbidden because Python 3.10 is supported.
25. Implement and validate the exact enrollment config/environment keys and bounds from §10.0.
26. PR-6 creates models/schema only; migration of real Go/Python agents and DB rows is performed in PR-15.
## Acceptance

```text
каждая из 20 identities имеет ровно один canonical V2 input type
C2EnrollmentIssueInput определён как closed frozen DTO с exact fields/bounds
supporting enums and aliases have one canonical owner and exact values from §10.0/§5.5
C2TargetOS/C2TargetArch and C2TransportConfig are fully defined and decoded
canonical enrollment bounds/config keys validate fail closed
V2InputUnion and ActionRequestV2 are defined exactly once in PR-6
ActionRequestV2 has exact fields from §10.14A and no authority/runtime state
TypedInputDecoderRegistry has exactly 20 exact decoders и fail closed для любого другого action_id
input decoder bindings match every exact action/schema row from §2.4
ни один decoder не принимает caller-created typed dataclass
нет open dict provider inputs
нет arbitrary command/output path
cleanup resource kind определяется canonical snapshot, не caller
control-plane task DTO отделён от agent-wire DTO
PR-6 не определяет task/result V12 wire DTO; их единственный owner — PR-15
нет typed-task → raw-command converter
каждый nested target извлекается executor-owned target schema
legacy ambiguous input fail closed с migration_required
```

## Тесты

```text
test_each_action_has_one_v2_input
test_v2_input_union_is_declared_once_and_exhaustive
test_action_request_v2_is_frozen
test_action_request_v2_exact_fields
test_action_request_v2_action_id_injected_from_catalog
test_action_request_v2_contains_no_authority_or_runtime_state
test_auth_foundation_enums_exact_values_and_single_owner
test_cancellation_token_is_executor_owned_and_non_serializable
test_action_policy_request_snapshot_exact_fields
test_child_bridge_requires_action_request_v2
test_pr6_adds_execution_bridge_and_v2_execution_source_aliases
test_pr6_adds_child_overload_to_single_run_v2_internal
test_child_reentry_action_identity_equality_required
test_child_reentry_request_id_matches_lease
test_child_reentry_lineage_matches_lease
test_child_identity_mismatch_happens_before_catalog_or_approval
test_input_schema_matrix_matches_decoder_registry
test_typed_input_decoder_registry_has_exactly_20_decoders
test_each_v2_action_decodes_to_expected_union_variant
test_decoder_rejects_caller_created_dataclass
test_unknown_v2_action_decoder_denied
test_unknown_fields_rejected
test_unknown_operation_id_rejected
test_unknown_transport_rejected
test_wrong_task_payload_variant_rejected
test_unknown_deployment_source_rejected
test_legacy_input_requires_explicit_migration
test_legacy_raw_command_not_auto_migrated
test_raw_command_cannot_populate_typed_fields
test_deploy_requires_enrollment_ref
test_deploy_requires_channel_and_session_refs
test_prebuilt_artifact_binding_fields_required
test_c2_deploy_input_v3_exact_fields
test_deployment_source_union_is_closed
test_c2_artifact_rebinding_request_exact_fields
test_c2_artifact_binding_digest_computed_before_staging
test_c2_artifact_stage_request_contains_full_binding_and_digest
test_stage_c2_artifact_never_accepts_build_output
test_cleanup_input_has_no_resource_kind
test_cleanup_backend_cannot_be_selected_by_caller
test_c2_enrollment_issue_input_exact_fields_and_bounds
test_remote_exec_service_enum_exact_values_and_single_owner
test_c2_deployment_profile_method_enum_exact_values_and_single_owner
test_dns_record_type_enum_exact_values_and_single_owner
test_c2_cleanup_reason_enum_exact_values_and_single_owner
test_c2_target_os_arch_enum_exact_values_and_single_owner
test_c2_transport_config_is_dns_only_until_new_leaf
test_enrollment_bound_config_defaults
test_enrollment_bound_environment_overrides
test_invalid_enrollment_bounds_fail_startup
test_pr6_does_not_redefine_target_scope_enums
test_control_task_and_agent_wire_models_are_distinct
test_v11_compat_is_decode_only
test_each_v2_input_has_target_schema
test_nested_hops_target_schema
test_destination_target_schema
test_bind_endpoint_target_schema
test_closed_unions_are_exhaustive
test_assert_never_imports_from_typing_extensions_on_python310
test_typing_extensions_is_explicit_runtime_dependency
test_runtime_requirement_change_regenerates_all_nine_profiles_all_targets
test_lock_manifest_input_hashes_match_requirement_sources
```

---
# PR-7. Adapter API V2 compatibility, typed results и transactional bound bases

## Цель

Добавить material-aware V2 API для 20 provider identities без массовой переписи существующих 96 adapters и встроить V2 result handling в executor-owned commit coordinator.

## CREATE

```text
core/actions/adapter_versions.py
core/actions/bound_adapters.py
core/actions/v1_compat.py
core/actions/result_schema_registry.py
tests/test_adapter_api_versions.py
tests/test_provider_results.py
tests/test_result_schema_registry.py
tests/test_bound_adapter_contracts.py
tests/test_existing_adapter_compatibility.py
tests/test_v2_transaction_participants.py
tests/test_composite_continuation_recovery.py
```

## MODIFY

```text
core/actions/base.py
core/actions/executor.py
core/actions/catalog.py
core/actions/models.py
core/actions/execution_commit.py
core/actions/provider_results.py
core/actions/provider_call_boundary.py
core/actions/composite_execution.py
core/actions/sensitive_transactions.py
core/actions/materials.py
core/actions/execution_results_v2.py
core/ai/sensitive_ingestor.py
core/execution/results.py
```

## Реализация

1. Не менять публичную V1 signature:
   ```python
   check(request)
   execute(request)
   verify(request, result)
   cleanup(request, result)
   ```
2. Зафиксировать для существующих adapters:
   ```text
   adapter_api_version=1
   ```
3. Реализовать и экспортировать единственный canonical
   `TypedActionAdapterV2` protocol из §12.2, расширив PR-1 structural header
   execute method; не объявлять второй class. Он не наследует `ActionAdapterV1`
   и не обязан реализовывать V1 methods. Для composite entries использовать
   только `TypedCompositeRouterV2` из §11.
4. `BoundMaterialBundle` создаётся только executor checkout coordinator и входит только в executor-built `BoundProviderInvocationContext`; он не может быть сконструирован из decoded request.
5. `execute_bound` receives the single `BoundProviderInvocationContext`.
   Required `check_bound` receives only `BoundProviderCheckContext`; required
   `verify_bound` receives only `ProviderResultReadViewV2` and
   `BoundProviderVerificationContext`. Neither non-execute phase has staging,
   participant registration, live/secret material or transaction lifecycle methods.
6. Executor dispatch разделить явно:
   ```text
   V1 → существующий lifecycle
   V2 → ingress/approval/facts/readiness/checkout/transaction/finally lifecycle
   ```
   This PR-7 modification is the first concrete wiring of PR-3 readiness and
   PR-4 checkout hooks to `ActionRequestV2`, `check_bound`, phase controllers,
   provider execution/route and verification. Earlier PRs remain dormant and
   independently importable.
7. V1 adapter никогда не получает:
   ```text
   BoundMaterialBundle
   InvocationScope V2
   ProviderStagingFacade
   ProviderParticipantRegistrationFacade
   ExecutionCommitCoordinator
   ```
8. V2 adapter никогда не вызывает legacy `cleanup(request, result)`; transient cleanup принадлежит `InvocationScope`.
9. Создать `ProviderResultSchemaRegistry` в `core/actions/result_schema_registry.py`:
   ```text
   key = ActionDescriptorV2.result_schema_id
   value = один exact closed ProviderResult decoder + ExecutionResultV2 publication contract
   ```
10. Catalog validation до mount требует, чтобы каждая V2 identity имела зарегистрированный
    `result_schema_id`; registry валидирует точную пару `(action_id, result_schema_id)`.
11. Неизвестный, дублированный или не соответствующий action `result_schema_id` fail closed до
    sensitive ingestion, resource staging и публикации execution result.
12. PR-7 является первым PR, который связывает строковый `result_schema_id` из PR-1 с concrete `ProviderResult` contracts. Public `ExecutionResultV2`/`ActionExecutionReportV2` уже существуют с PR-2 и здесь не переопределяются.
## Execution-result publication and finalization ownership

`core/actions/execution_results_v2.py` is created in PR-2; `core/actions/execution_finalization.py`
and `core/actions/execution_result_store.py` are created in PR-5. PR-2 owns only
public status/result/ref/report/finalization-reference DTOs. PR-5 owns
`NormalizedExecutionResultDraftV2`, its digest, hidden/binding DTOs and the
`ExecutionResultStore` protocol in `execution_result_store.py`; this avoids a
runtime import cycle with `execution_commit.py`. PR-7 imports these owners and
adds only the exhaustive ProviderResult→normalized projection/registry binding;
it does not redeclare the store foundation.

```python
@dataclass(frozen=True)
class NormalizedExecutionResultDraftV2:
    transaction_id: str
    execution_id: str
    action_id: str
    status: Literal[ExecutionStatusV2.SUCCEEDED, ExecutionStatusV2.PARTIAL]
    reason_codes: tuple[str, ...]
    artifact_drafts: tuple[ArtifactDraftRefV2, ...]
    sensitive_batch_drafts: tuple[SensitiveBatchDraftRefV2, ...]
    managed_resource_drafts: tuple[ManagedResourceDraftRefV2, ...]
    observation_drafts: tuple[ObservationDraftRefV2, ...]
    fact_drafts: tuple[FactDraftRefV2, ...]
    audit_outbox_draft: AuditOutboxDraftRefV2
    decision_trace_draft: DecisionTraceDraftRefV2
    linked_result_refs: tuple[ExecutionResultRefV2, ...]
    provenance_chain: tuple[str, ...]
    prepare_dependency_registrations: tuple[ParticipantRegistrationRefV2, ...]
    commit_dependency_registrations: tuple[ParticipantRegistrationRefV2, ...]
    normalized_draft_digest: str


def canonical_normalized_execution_result_draft_digest(
    draft: NormalizedExecutionResultDraftV2,
) -> str:
    """RFC-8785 digest tagged normalized-execution-result/2.0."""
    ...


@dataclass(frozen=True)
class HiddenExecutionResultCommitV2:
    transaction_id: str
    hidden_ref: HiddenExecutionResultCommitRefV2
    execution_result: ExecutionResultV2
    execution_result_ref: ExecutionResultRefV2
    participant_binding_digest: str
    hidden_commit_digest: str


@dataclass(frozen=True)
class StagedExecutionResultV2:
    draft_ref: ExecutionResultDraftRefV2
    registration_ref: ParticipantRegistrationRefV2


@dataclass(frozen=True)
class ParticipantHiddenCommitBindingV2:
    participant_id: str
    participant_kind: ParticipantKindV2
    prepare_revision: int
    commit_revision: int
    prepare_receipt_digest: str
    commit_receipt_digest: str
    resolved_references: tuple[ResolvedDraftReferenceV2, ...]


@runtime_checkable
class ExecutionResultStore(Protocol):
    def stage(
        self,
        transaction_id: str,
        draft: NormalizedExecutionResultDraftV2,
    ) -> StagedExecutionResultV2: ...

    def commit_hidden(
        self,
        draft: ExecutionResultDraftRefV2,
        participant_bindings: tuple[ParticipantHiddenCommitBindingV2, ...],
    ) -> HiddenExecutionResultCommitV2: ...

    def require_hidden(
        self,
        reference: HiddenExecutionResultCommitRefV2,
    ) -> HiddenExecutionResultCommitV2: ...

    def bind_committed(
        self,
        hidden: HiddenExecutionResultCommitV2,
        committed_marker: CommittedExecutionMarkerV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> CommittedExecutionResultBindingV2: ...

    def get(self, reference: ExecutionResultRefV2) -> ExecutionResultV2: ...


@runtime_checkable
class InvocationFinalizationStore(Protocol):
    def persist_or_enqueue(
        self,
        record: InvocationFinalizationRecordV2,
        *,
        intent_ref: InvocationFinalizationIntentRefV2,
        ownership_ref: ExecutionReportOwnershipRefV2,
    ) -> FinalizationPersistenceOutcomeV2: ...


@dataclass(frozen=True)
class ReportQueryRequestV2:
    request_id: str
    execution_id: str


@runtime_checkable
class ExecutionReportQueryServiceV2(Protocol):
    def get_latest_report(
        self,
        *,
        request: ReportQueryRequestV2,
        ingress_lease: IngressInvocationLease,
    ) -> ExecutionReportViewV2: ...


@runtime_checkable
class ExecutionReportStoreV2(Protocol):
    def publish_final(
        self,
        report: ActionExecutionReportV2,
        *,
        expected_previous_revision: int | None,
        publication_idempotency_key: str,
    ) -> ActionExecutionReportEnvelopeV2: ...
    def publish_progress(
        self,
        report: ExecutionProgressDraftV2,
        *,
        expected_previous_revision: int | None,
        publication_idempotency_key: str,
    ) -> ExecutionProgressReportV2: ...
```

The execution-result store is an `ExecutionCommitParticipant`. The normalized
draft contains only transaction-private draft refs and exact phased participant
dependencies. The executor derives both sets from the staging registry;
providers/callers cannot supply them. `prepare_dependency_registrations` is the
exact unique set of reversible source participants needed to validate the draft
before dispatch. `commit_dependency_registrations` covers every final-ref
source and equals that set plus the terminal external-effect participant when
the action has one. Missing, extra or duplicate registrations fail closed.
`ExecutionResultStore.stage()` writes the draft and atomically registers the
EXECUTION_RESULT participant with those exact prepare/commit edge sets,
returning
`StagedExecutionResultV2`; no orphan stage→registration window exists. Its
participant prepares after every reversible source participant and before the
terminal effect; during hidden commit it waits for every commit dependency and
resolves exact prepare/commit
receipts to final opaque
refs and constructs an unavailable `ExecutionResultV2` plus hidden ref. Neither
is normally readable yet. After all finalization receipts are durable, the
coordinator store CASes its record to `COMMITTED`, reads it back and store-issues
with a canonical digest a
`CommittedExecutionMarkerV2`; only then does the result store re-read/verify the
marker and idempotently `bind_committed(hidden, committed_marker)` and mint the
private-token binding. Recovery replays this post-marker binding without
rerunning a provider or participant effect. The finalization
store is deliberately outside that transaction and runs only after outer
cleanup. No code may require a cleanup field inside `ExecutionResultV2`.
The execution-result commit receipt copies exactly
`HiddenExecutionResultCommitV2.hidden_ref`; recovery calls `require_hidden()`
and revalidates transaction/execution/draft/digests before binding. The result
participant's own `resolved_references` may be empty because its public result
ref is minted only after the global committed marker.

Each participant commit receipt contains coordinator-created
`ResolvedDraftReferenceV2` entries; the result participant never invents them.
There is exactly one binding per source draft. Artifact→ARTIFACT,
managed-resource→SESSION/ROUTE/C2_RESOURCE, fact/observation→FACT,
audit→AUDIT and trace→DECISION_TRACE are closed by source/resource kind;
sensitive batch maps to one or more CREDENTIAL refs; FACT refs arise only from
direct FactDraft bindings (sealed secret records remain internal and are never
result refs). `RESOLVED` requires one or
more final refs and null no-fact fields. `NO_FACT` is permitted only for an
OBSERVATION source, requires an empty final tuple and non-null durable
`no_fact_receipt_ref/digest`. All other combinations, duplicate source IDs or
duplicate final refs fail closed.
Finalization changes visibility only; it never changes reference identity.

`ExecutionReportQueryServiceV2`, not the result participant store, joins the
committed binding with finalization/termination/reconciliation revisions. It
requires a fresh single-use ingress lease whose `bound_request_id` equals
`ReportQueryRequestV2.request_id`, loads and digest-validates the immutable
`ExecutionReportOwnershipBindingV2` registered once at execution creation,
authorizes its original mission/action/owner scope, and consumes the query
lease in its own `finally`. The original execution lease is never reused. It
returns the highest durable report revision. A pending report remains immutable;
a later COMMITTED reconciliation creates a new report revision bound to the same
execution/transaction and committed marker.
`ExecutionReportStoreV2.publish_final()` canonical-encodes the entire report,
assigns a monotonic per-execution revision/ref/digest and returns the envelope;
the query service always returns the envelope for final reports and verifies its
digest. Progress and final report revision spaces share one CAS sequence.
Both publish methods require expected-previous-revision CAS and a stable
idempotency key. An identical `(execution_id, key, canonical draft/report
digest)` replay returns the same record; conflicting CAS/digest fails. No
progress may overwrite a final envelope, and at most one progress→final
transition is accepted per revision. Progress input has no revision/ref/digest;
only the store mints those fields.

`canonical_normalized_execution_result_draft_digest()` excludes its own digest
field and hashes all other exact tagged fields. Stage recomputes it, compares it
with `ExecutionResultDraftRefV2.normalized_draft_digest`, and uses golden vectors.
For a composite result `linked_result_refs` is exactly the single verified child
ref from `CompositeProviderResult`; for every non-composite result it is exactly
`()`. The final `ExecutionResultV2` preserves the same tuple and both canonical
draft/final digests cover it.

A composite router handles the child outcome only through:

```python
child_outcome = context.child_execution.run_selected_child(spec=child_spec)
match child_outcome:
    case ActionExecutionReportEnvelopeV2() as child_envelope:
        child_report = child_envelope.report
        child_result_ref = child_report.require_successful_committed_result_ref()
        route_outcome = CompositeProviderResult(
            child_action_id=child_spec.selected_child_action_id,
            child_execution_id=child_report.execution_id,
            child_result_ref=child_result_ref,
            ...,
        )
    case ExecutionProgressReportV2() as progress:
        route_outcome = CompositeRouteProgressV2(child_progress=progress)
    case unexpected:
        assert_never(unexpected)
```

The concrete facade also validates `child_envelope.report_ref`, revision and
canonical digest against the store read-back before minting its private child
completion receipt; a raw `ActionExecutionReportV2` is never an invocation
outcome.

The method succeeds only when the child result participant is globally
`COMMITTED`. A child terminal failure raises no committed result, and a pending
child yields `CompositeRouteProgressV2`; neither can synthesize
`CompositeProviderResult`.

## Closed provider results — exact enums, support DTO и variant fields

PR-5 creates the staging/result foundation in `core/actions/provider_results.py`:

```text
ProviderOutcomeV2
ManagedResourceKind
ProviderProvenanceV2
ProviderResultHeaderV2
ObservationDraftRefV2
ArtifactDraftRefV2
ManagedResourceDraftRefV2
SensitiveHandleStateV2
SensitiveBatchDraftRefV2
SensitiveObservationHandleV2
SensitiveBatchHandleV2
ProviderResultFoundationV2
```

This makes PR-5 independently type-checkable together with
`BoundProviderInvocationContext`. PR-7 modifies the same module only to add
`ProviderResultKind` and the exact closed result variants/union; it does not
redeclare the foundation DTOs.

`core/actions/provider_results.py` is shown below in final-tree import order.
PR-5 creates the kind-independent foundation (`ProviderOutcomeV2`,
`PartialCommitDispositionV2`, the normalization result/token,
`ManagedResourceKind`, provenance and draft/handle DTOs).  It does **not**
define, import or annotate `ProviderResultKind`.  PR-7 first adds
`ProviderResultKind`, then adds the result-kind-dependent
`PartialCommitRuleV2`, policy snapshot/registry/policy and
`ProviderOutcomeNormalizerV2`, followed by the closed result variants.  Those
PR-7-owned symbols are displayed here only to make the final import order exact;
they are absent from the independently type-checked PR-5 tree.

```python
class ProviderOutcomeV2(str, Enum):
    SUCCEEDED = "succeeded"
    PARTIAL = "partial"
    FAILED = "failed"
    UNAVAILABLE = "unavailable"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class ProviderResultKind(str, Enum):
    OPERATION = "operation"
    ARTIFACT = "artifact"
    CREDENTIAL = "credential"
    SESSION = "session"
    ROUTE = "route"
    C2_RESOURCE = "c2_resource"
    COMPOSITE = "composite"
    SENSITIVE = "sensitive"


class PartialCommitDispositionV2(str, Enum):
    ACCEPT = "accept"
    REJECT = "reject"


class _ProviderOutcomeNormalizationConstructionTokenV2:
    pass


@dataclass(frozen=True, init=False)
class ProviderOutcomeNormalizationV2:
    provider_outcome: ProviderOutcomeV2
    execution_status: ExecutionStatusV2
    commit_eligible: bool
    partial_disposition: PartialCommitDispositionV2 | None

    @classmethod
    def _from_normalizer(
        cls,
        *,
        _token: _ProviderOutcomeNormalizationConstructionTokenV2,
        provider_outcome: ProviderOutcomeV2,
        execution_status: ExecutionStatusV2,
        commit_eligible: bool,
        partial_disposition: PartialCommitDispositionV2 | None,
    ) -> ProviderOutcomeNormalizationV2: ...


@dataclass(frozen=True)
class PartialCommitRuleV2:
    action_id: str
    result_kind: ProviderResultKind
    accepted_reason_codes: tuple[str, ...]


@dataclass(frozen=True)
class PartialCommitPolicySnapshotV2:
    policy_id: str
    revision: int
    rules: tuple[PartialCommitRuleV2, ...]
    policy_digest: str


def canonical_partial_commit_policy_digest(
    snapshot: PartialCommitPolicySnapshotV2,
) -> str:
    """Canonical digest excluding policy_digest itself."""
    ...


@runtime_checkable
class PartialCommitPolicyRegistryV2(Protocol):
    def require_current(
        self,
        action_id: str,
    ) -> PartialCommitPolicySnapshotV2: ...
    def assert_current(self, snapshot: PartialCommitPolicySnapshotV2) -> None: ...


@runtime_checkable
class PartialCommitPolicyV2(Protocol):
    def decide(
        self,
        *,
        snapshot: PartialCommitPolicySnapshotV2,
        action_id: str,
        result_kind: ProviderResultKind,
        reason_codes: tuple[str, ...],
    ) -> PartialCommitDispositionV2: ...


class ProviderOutcomeNormalizerV2:
    """Sole factory; validates the immutable normalization matrix."""

    _construction_token: _ProviderOutcomeNormalizationConstructionTokenV2
    _policy: PartialCommitPolicyV2
    _registry: PartialCommitPolicyRegistryV2

    def normalize(
        self,
        *,
        action_id: str,
        result_kind: ProviderResultKind,
        outcome: ProviderOutcomeV2,
        reason_codes: tuple[str, ...],
        partial_policy: PartialCommitPolicySnapshotV2,
    ) -> ProviderOutcomeNormalizationV2: ...


class ManagedResourceKind(str, Enum):
    SESSION = "session"
    PIVOT_ROUTE = "pivot_route"
    C2_CHANNEL = "c2_channel"
    C2_ENROLLMENT = "c2_enrollment"
    C2_AGENT = "c2_agent"
    C2_TASK = "c2_task"
    DEPLOYMENT = "deployment"


@dataclass(frozen=True)
class ProviderProvenanceV2:
    implementation_id: str
    implementation_version: str
    request_digest: str
    started_at: float
    completed_at: float


@dataclass(frozen=True)
class ProviderResultHeaderV2:
    schema_version: Literal["2.0"]
    provider_id: str
    outcome: ProviderOutcomeV2
    reason_codes: tuple[str, ...]
    duration_ms: int
    provenance: ProviderProvenanceV2


@runtime_checkable
class ProviderResultFoundationV2(Protocol):
    @property
    def header(self) -> ProviderResultHeaderV2: ...


@dataclass(frozen=True)
class ObservationDraftRefV2:
    transaction_id: str
    draft_id: str
    observation_schema_id: str
    payload_digest: str


@dataclass(frozen=True)
class NonSensitiveArtifactDraftRefV2:
    transaction_id: str
    draft_id: str
    artifact_kind: ArtifactKind
    content_digest: str
    size: int
    media_type: str
    target: str | None


@dataclass(frozen=True)
class SensitiveArtifactDraftRefV2:
    transaction_id: str
    draft_id: str
    artifact_kind: ArtifactKind
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    size: int
    media_type: str
    target: str | None


ArtifactDraftRefV2: TypeAlias = NonSensitiveArtifactDraftRefV2 | SensitiveArtifactDraftRefV2


@dataclass(frozen=True)
class ManagedResourceDraftRefV2:
    transaction_id: str
    draft_id: str
    resource_kind: ManagedResourceKind
    target: str | None
    lifecycle_owner: str
    close_action_id: str | None
    expires_at: float | None


class SensitiveHandleStateV2(str, Enum):
    OPEN = "open"
    STAGING = "staging"
    CONSUMED = "consumed"
    CLEARED = "cleared"


@runtime_checkable
class SensitiveIntegrityAuthenticatorV2(Protocol):
    def compute(
        self,
        *,
        domain: str,
        source: memoryview,
    ) -> SensitiveIntegrityTagV2: ...
    def verify(
        self,
        *,
        expected: SensitiveIntegrityTagV2,
        source: memoryview,
    ) -> Literal[True]: ...
    def new_stream(
        self,
        *,
        domain: str,
        expected_total_bytes: int,
    ) -> SensitiveIntegrityStreamV2: ...


@runtime_checkable
class SensitiveIntegrityStreamV2(Protocol):
    @property
    def state(self) -> SensitiveIntegrityStreamStateV2: ...
    def update(self, view: memoryview) -> None: ...
    def finalize(self) -> SensitiveIntegrityTagV2: ...
    def abort_and_zeroize(self) -> None: ...
    def __enter__(self) -> SensitiveIntegrityStreamV2: ...
    def __exit__(self, exc_type: object, exc: object, tb: object) -> None: ...


class SensitiveIntegrityStreamStateV2(str, Enum):
    OPEN = "open"
    FINALIZED = "finalized"
    ABORTED = "aborted"


@runtime_checkable
class SensitiveIntegrityKeyLeaseV2(Protocol):
    @property
    def key_id(self) -> str: ...
    @property
    def state(self) -> SensitiveIntegrityKeyLeaseStateV2: ...
    def transfer_once_to_stream(
        self,
        *,
        domain: str,
        expected_total_bytes: int,
        authenticator_provenance_id: str,
    ) -> SensitiveIntegrityStreamV2: ...
    def close_and_zeroize(self) -> None: ...


class SensitiveIntegrityKeyLeaseStateV2(str, Enum):
    OPEN = "open"
    TRANSFERRED = "transferred"
    CLOSED = "closed"


@runtime_checkable
class SensitiveIntegrityKeyringV2(Protocol):
    def active_key_id(self) -> str: ...
    def acquire_for_authenticator(
        self,
        *,
        key_id: str,
        authenticator_provenance_id: str,
    ) -> SensitiveIntegrityKeyLeaseV2: ...


class _SensitiveAuthenticatorConstructionTokenV2:
    pass


class OwnedSensitiveIntegrityKeyLeaseV2(SensitiveIntegrityKeyLeaseV2):
    """Final non-exporting concrete lease with OPEN→TRANSFERRED|CLOSED state."""

    ...


class OwnedHmacSensitiveIntegrityStreamV2(SensitiveIntegrityStreamV2):
    """Final streaming HMAC implementation; zeroizes key state on terminal."""

    ...


class PersistentSensitiveIntegrityKeyringV2(SensitiveIntegrityKeyringV2):
    """Final persistent key-id resolver retaining verification-only rotations."""

    ...


@final
class OwnedHmacSensitiveIntegrityAuthenticatorV2:
    """Final executor/store authenticator; key material is never exported."""

    _keyring: SensitiveIntegrityKeyringV2
    _provenance_id: str
    _construction_token: _SensitiveAuthenticatorConstructionTokenV2

    def __init__(
        self,
        *,
        _token: _SensitiveAuthenticatorConstructionTokenV2,
        keyring: PersistentSensitiveIntegrityKeyringV2,
        provenance_id: str,
    ) -> None: ...

    def compute(self, *, domain: str, source: memoryview) -> SensitiveIntegrityTagV2: ...
    def verify(
        self,
        *,
        expected: SensitiveIntegrityTagV2,
        source: memoryview,
    ) -> Literal[True]: ...
    def new_stream(
        self,
        *,
        domain: str,
        expected_total_bytes: int,
    ) -> SensitiveIntegrityStreamV2: ...


class OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2:
    """Sole holder of the module-private construction token."""

    _construction_token: _SensitiveAuthenticatorConstructionTokenV2

    def create(
        self,
        *,
        keyring: PersistentSensitiveIntegrityKeyringV2,
        provenance_id: str,
    ) -> OwnedHmacSensitiveIntegrityAuthenticatorV2: ...


@dataclass(frozen=True)
class SensitiveArtifactSealReceiptV2:
    transaction_id: str
    draft_id: str
    envelope_version: Literal["sensitive-artifact-envelope/1"]
    cipher_id: Literal["aes-256-gcm"]
    wrapping_key_id: str
    nonce_ref: str
    sealed_record_digest: str
    plaintext_size: int
    ciphertext_size: int
    receipt_digest: str


class SensitiveArtifactEnvelopeWriterStateV2(str, Enum):
    OPEN = "open"
    SEALED = "sealed"
    ABORTED = "aborted"


@dataclass(frozen=True)
class SensitiveArtifactEnvelopeAadV2:
    transaction_id: str
    draft_id: str
    artifact_kind: ArtifactKind
    target: str | None
    media_type: str
    integrity_domain: str
    aad_digest: str


@dataclass(frozen=True)
class SensitiveArtifactDraftReservationV2:
    reservation_ref: str
    transaction_id: str
    draft_id: str
    aad: SensitiveArtifactEnvelopeAadV2
    expected_size: int
    reservation_revision: int
    reservation_digest: str


class SensitiveArtifactReservationStateV2(str, Enum):
    RESERVED = "reserved"
    OPEN = "open"
    SEALED = "sealed"
    STAGED = "staged"
    TRANSFERRED = "transferred"
    ABORTED = "aborted"


@dataclass(frozen=True)
class SensitiveArtifactAbortReceiptV2:
    transaction_id: str
    draft_id: str
    wrapping_key_destroyed: Literal[True]
    envelope_revoked: Literal[True]
    receipt_digest: str


@dataclass(frozen=True)
class SealedArtifactTransientTransferReceiptV2:
    reservation_ref: str
    transaction_id: str
    draft_id: str
    backend_transient_receipt: BackendOwnedTransientReceiptV2
    sealed_record_digest: str
    integrity_tag: SensitiveIntegrityTagV2
    transfer_digest: str


@dataclass(frozen=True)
class SensitiveArtifactReservationRecordV2:
    reservation: SensitiveArtifactDraftReservationV2
    state: SensitiveArtifactReservationStateV2
    reservation_revision: int
    seal_receipt: SensitiveArtifactSealReceiptV2 | None
    abort_receipt: SensitiveArtifactAbortReceiptV2 | None
    staged_artifact: StagedArtifactV2 | None
    transfer_receipt: SealedArtifactTransientTransferReceiptV2 | None
    record_digest: str


@dataclass(frozen=True, repr=False)
class SensitiveArtifactWriterOpenV2:
    record: SensitiveArtifactReservationRecordV2
    writer: SensitiveArtifactEnvelopeWriterV2 = field(repr=False, compare=False)


def canonical_sensitive_artifact_aad_digest(aad: SensitiveArtifactEnvelopeAadV2) -> str: ...
def canonical_sensitive_artifact_reservation_digest(
    reservation: SensitiveArtifactDraftReservationV2,
) -> str: ...
def canonical_sensitive_artifact_seal_digest(
    receipt: SensitiveArtifactSealReceiptV2,
) -> str: ...
def canonical_sensitive_artifact_abort_digest(
    receipt: SensitiveArtifactAbortReceiptV2,
) -> str: ...
def canonical_sensitive_artifact_transfer_digest(
    receipt: SealedArtifactTransientTransferReceiptV2,
) -> str: ...
def canonical_sensitive_artifact_reservation_record_digest(
    record: SensitiveArtifactReservationRecordV2,
) -> str: ...


@runtime_checkable
class SensitiveArtifactEnvelopeWriterV2(Protocol):
    @property
    def state(self) -> SensitiveArtifactEnvelopeWriterStateV2: ...
    @property
    def aad(self) -> SensitiveArtifactEnvelopeAadV2: ...
    def write_view(self, view: memoryview) -> None: ...
    def finalize(self) -> SensitiveArtifactSealReceiptV2: ...
    def abort_and_destroy_wrapping_key(self) -> SensitiveArtifactAbortReceiptV2: ...


@runtime_checkable
class SensitiveArtifactEnvelopeWriterFactoryV2(Protocol):
    def reserve_draft(
        self,
        *,
        transaction_id: str,
        artifact_kind: ArtifactKind,
        target: str | None,
        media_type: str,
        expected_size: int,
        integrity_domain: str,
    ) -> SensitiveArtifactReservationRecordV2: ...
    def open_for_reservation(
        self,
        *,
        reservation: SensitiveArtifactReservationRecordV2,
        expected_revision: int,
        authenticator: OwnedHmacSensitiveIntegrityAuthenticatorV2,
    ) -> SensitiveArtifactWriterOpenV2: ...
    def checkpoint_sealed(
        self,
        *,
        opened: SensitiveArtifactWriterOpenV2,
        expected_revision: int,
        receipt: SensitiveArtifactSealReceiptV2,
    ) -> SensitiveArtifactReservationRecordV2: ...
    def accept_sealed_ownership(
        self,
        *,
        reservation: SensitiveArtifactReservationRecordV2,
        receipt: SensitiveArtifactSealReceiptV2,
        integrity_tag: SensitiveIntegrityTagV2,
        prepare_depends_on: tuple[ParticipantRegistrationRefV2, ...],
        commit_depends_on: tuple[ParticipantRegistrationRefV2, ...],
    ) -> StagedArtifactV2: ...
    def transfer_sealed_to_backend_transient(
        self,
        *,
        reservation: SensitiveArtifactReservationRecordV2,
        receipt: SensitiveArtifactSealReceiptV2,
        integrity_tag: SensitiveIntegrityTagV2,
        scope_id: str,
        phase_lease: ProviderExecutePhaseLeaseV2,
    ) -> SealedArtifactTransientTransferReceiptV2: ...
    def require(
        self,
        reservation_ref: str,
    ) -> SensitiveArtifactReservationRecordV2: ...
    def list_reconcilable(self) -> tuple[str, ...]: ...
    def revoke_unconsumed(
        self,
        reservation: SensitiveArtifactReservationRecordV2,
        operation: CleanupOperationContextV2,
    ) -> SensitiveArtifactReservationRecordV2: ...


@runtime_checkable
class ZeroizableSensitiveBufferV2(Protocol):
    @property
    def buffer_id(self) -> str: ...
    @property
    def byte_length(self) -> int: ...
    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...
    @property
    def zeroized(self) -> bool: ...

    def acquire_single_use(
        self,
        *,
        consumer_id: str,
    ) -> ZeroizableSensitiveBufferLeaseV2: ...

    def zeroize(self) -> None: ...


@runtime_checkable
class ZeroizableSensitiveBufferLeaseV2(Protocol):
    @property
    def buffer_id(self) -> str: ...
    @property
    def lease_id(self) -> str: ...
    @property
    def byte_length(self) -> int: ...
    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...
    def read_into(self, destination: ZeroizableDestinationBufferV2) -> int: ...
    def close_and_zeroize(self) -> None: ...


class ZeroizableDestinationBufferV2:
    """Concrete owned mutable destination; context exit always overwrites/closes it."""

    _buffer_id: str
    _storage: bytearray | mmap.mmap
    _capacity: int
    _closed: bool
    _zeroized: bool

    @classmethod
    def allocate(cls, capacity: int) -> ZeroizableDestinationBufferV2: ...
    def __enter__(self) -> ZeroizableDestinationBufferV2: ...
    def __exit__(self, exc_type: object, exc: object, tb: object) -> None: ...
    def borrow_writable_view(self) -> ContextManager[memoryview]: ...
    def zeroize_and_close(self) -> None: ...
    @property
    def zeroized(self) -> bool: ...


class OwnedZeroizableSensitiveBufferV2:
    """Concrete owned bytearray/anonymous-mmap implementation."""

    _buffer_id: str
    _storage: bytearray | mmap.mmap
    _byte_length: int
    _integrity_tag: SensitiveIntegrityTagV2
    _lease_id: str | None
    _zeroized: bool
    _lock: threading.RLock

    @property
    def buffer_id(self) -> str: ...
    @property
    def byte_length(self) -> int: ...
    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...
    @property
    def zeroized(self) -> bool: ...

    def acquire_single_use(self, *, consumer_id: str) -> ZeroizableSensitiveBufferLeaseV2: ...
    def zeroize(self) -> None: ...


class OwnedZeroizableSensitiveBufferFactoryV2:
    """Executor/store-owned factory; holds the authenticator privately."""

    _authenticator: OwnedHmacSensitiveIntegrityAuthenticatorV2

    def from_owned_mutable(
        self,
        *,
        source: bytearray,
        domain: str,
    ) -> OwnedZeroizableSensitiveBufferV2:
        """Authenticate/copy into owned storage and wipe source in finally."""
        ...


class OwnedZeroizableSensitiveBufferLeaseV2:
    """Concrete single-use lease; read_into accepts only ZeroizableDestinationBufferV2."""

    _owner: OwnedZeroizableSensitiveBufferV2
    _lease_id: str
    _closed: bool

    @property
    def buffer_id(self) -> str: ...
    @property
    def lease_id(self) -> str: ...
    @property
    def byte_length(self) -> int: ...
    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...
    def read_into(self, destination: ZeroizableDestinationBufferV2) -> int: ...
    def close_and_zeroize(self) -> None: ...


@dataclass(frozen=True, repr=False)
class ZeroizableSensitiveBatchStageRequestV2:
    schema_id: str
    transaction_id: str
    factory_id: str
    factory_provenance_digest: str
    source_handle_id: str
    expected_item_count: int
    expected_integrity_tag: SensitiveIntegrityTagV2
    expected_total_bytes: int
    buffer_lease: ZeroizableSensitiveBufferLeaseV2 = field(
        repr=False,
        compare=False,
    )


@dataclass(frozen=True)
class SensitiveBatchDraftRefV2:
    transaction_id: str
    draft_id: str
    schema_id: str
    factory_id: str
    factory_provenance_digest: str
    source_handle_id: str
    item_count: int
    integrity_tag: SensitiveIntegrityTagV2
    total_bytes: int


@runtime_checkable
class SensitiveBatchStagingCapabilityV2(Protocol):
    """Executor-internal; never present in BoundProviderInvocationContext."""

    @property
    def transaction_id(self) -> str: ...
    def stage_zeroizable_sensitive_batch(
        self,
        request: ZeroizableSensitiveBatchStageRequestV2,
    ) -> StagedSensitiveBatchV2: ...


class _SensitiveHandleConstructionTokenV2:
    pass


class OwnedSensitiveObservationHandleV2:
    """Final core-owned one-shot handle; provider subclasses are rejected."""

    _construction_token: _SensitiveHandleConstructionTokenV2
    _buffer: OwnedZeroizableSensitiveBufferV2
    _phase_lease: ProviderExecutePhaseLeaseV2
    _lock: threading.RLock

    def __init__(
        self,
        *,
        _token: _SensitiveHandleConstructionTokenV2,
        schema_id: str,
        transaction_id: str,
        factory_id: str,
        factory_provenance_digest: str,
        item_count: int,
        buffer: OwnedZeroizableSensitiveBufferV2,
        phase_lease: ProviderExecutePhaseLeaseV2,
    ) -> None: ...

    @property
    def schema_id(self) -> str: ...
    @property
    def transaction_id(self) -> str: ...
    @property
    def factory_id(self) -> str: ...
    @property
    def factory_provenance_digest(self) -> str: ...
    @property
    def handle_id(self) -> str: ...
    @property
    def state(self) -> SensitiveHandleStateV2: ...
    @property
    def item_count(self) -> int: ...
    @property
    def integrity_tag(self) -> SensitiveIntegrityTagV2: ...
    @property
    def total_bytes(self) -> int: ...

    def stage_into(
        self,
        staging: SensitiveBatchStagingCapabilityV2,
        *,
        expected_handle_id: str,
        expected_schema_id: str,
        expected_transaction_id: str,
        expected_factory_id: str,
        expected_item_count: int,
        expected_integrity_tag: SensitiveIntegrityTagV2,
        expected_total_bytes: int,
    ) -> StagedSensitiveBatchV2: ...

    def clear(self) -> None: ...


@runtime_checkable
class SensitiveObservationHandleFactoryV2(Protocol):
    """Narrow execute-phase factory backed by core-owned mutable storage."""

    @property
    def transaction_id(self) -> str: ...
    @property
    def factory_id(self) -> str: ...
    @property
    def provenance_digest(self) -> str: ...
    def create_from_mutable(
        self,
        *,
        schema_id: str,
        item_count: int,
        source: bytearray,
    ) -> OwnedSensitiveObservationHandleV2: ...


class OwnedSensitiveObservationHandleFactoryV2:
    """Final executor-owned production factory; not subclassable or decoded."""

    _construction_token: _SensitiveHandleConstructionTokenV2
    _transaction_id: str
    _factory_id: str
    _provenance_digest: str
    _phase_lease: ProviderExecutePhaseLeaseV2
    _buffer_factory: OwnedZeroizableSensitiveBufferFactoryV2
    _lock: threading.RLock

    @property
    def transaction_id(self) -> str: ...
    @property
    def factory_id(self) -> str: ...
    @property
    def provenance_digest(self) -> str: ...
    def create_from_mutable(
        self,
        *,
        schema_id: str,
        item_count: int,
        source: bytearray,
    ) -> OwnedSensitiveObservationHandleV2: ...


SensitiveObservationHandleV2: TypeAlias = OwnedSensitiveObservationHandleV2


@dataclass(frozen=True, repr=False)
class SensitiveBatchHandleV2:
    schema_id: str
    transaction_id: str
    factory_id: str
    factory_provenance_digest: str
    handle_id: str
    item_count: int
    integrity_tag: SensitiveIntegrityTagV2
    total_bytes: int
    handle: OwnedSensitiveObservationHandleV2 = field(repr=False, compare=False)
```

There is no public/keyless owned-buffer constructor. The concrete buffer
factory is injected into `SecretStore`, `LegacySecretValueAdapterV2` and
`OwnedSensitiveObservationHandleFactoryV2`; providers never receive the
authenticator or its key. Integrity tags are domain-separated by schema and
purpose, carry a rotatable `key_id`, and are compared with
`hmac.compare_digest`. The persistent keyring retains verification-only keys for
every live tag across restart/rotation and startup fails closed on an unknown
key ID. Key bytes never cross the concrete final authenticator. Opaque tags may
appear in transaction-scoped snapshot/material/draft DTOs, but providers cannot
mint or verify them and they never enter reports or audit payloads. Custom
structural authenticators are rejected by exact type/provenance checks. Success
and every factory exception path wipe the complete owned `bytearray`; readonly,
sliced, aliased or arbitrary memoryview sources are rejected. A wrong domain,
unknown key or tag mismatch fails before any draft is accepted.

Production accepts only exact `PersistentSensitiveIntegrityKeyringV2`,
`OwnedSensitiveIntegrityKeyLeaseV2`,
`OwnedHmacSensitiveIntegrityStreamV2` and the authenticator created by
`OwnedHmacSensitiveIntegrityAuthenticatorFactoryV2` with its module-private
identity token; structural/custom implementations are test-only and rejected by
buffer/artifact/secret factories. The MAC input is exactly:

```text
ASCII "octopus-sensitive-integrity/1\0"
u16be(len(UTF-8 domain)) || UTF-8 domain
u64be(total plaintext byte length)
plaintext bytes in order
```

`domain` is NFC UTF-8, 1..255 bytes and contains no NUL; `key_id` is ASCII
`[A-Za-z0-9._-]{1,64}`; algorithm is exactly `hmac-sha256-v2`; the tag is the
32-byte HMAC encoded as 43-character unpadded base64url. `new_stream()` requires
the bounded executor/store-verified `expected_total_bytes` up front, MACs it before the first
chunk, counts every update and refuses finalize unless the exact length was
received; every chunking must equal one-shot compute without buffering the whole
artifact.
Verification decodes exactly 32 bytes and uses constant-time comparison. Golden
one-shot/chunked/rotation vectors lock framing and encoding across runtimes.

Key acquisition is one-shot: the concrete authenticator obtains an opaque
`SensitiveIntegrityKeyLeaseV2`, transfers it exactly once into an OPEN stream,
and closes/zeroizes the lease in `finally`. The stream permits updates only
while OPEN and exactly one `finalize()` (OPEN→FINALIZED) or
`abort_and_zeroize()` (OPEN→ABORTED); context exit aborts any still-open stream.
No lease exposes key bytes or a general cryptographic primitive.
`SensitiveArtifactEnvelopeWriterFactoryV2` is ArtifactStore-owned and binds one
transaction/draft/AAD/domain/authenticator provenance. Its writer has the same
OPEN→SEALED|ABORTED one-shot lifecycle. The store accepts ownership only when
seal receipt, keyed tag, AAD, transaction/draft and atomic artifact participant
registration all match. The store first mints and read-backs a durable
`SensitiveArtifactReservationRecordV2` and its AAD/draft ID; callers never
select them. Before OPEN it attaches a closed recoverable cleanup descriptor to
the current scope/intent. `open_for_reservation(expected_revision=...)` CASes
RESERVED→OPEN, read-backs the new record and returns it together with the
non-serializable writer in `SensitiveArtifactWriterOpenV2`; callers never keep
using the stale RESERVED revision. `checkpoint_sealed(opened,
expected_revision=...)` accepts only that OPEN session and CASes/read-backs
OPEN→SEALED before ownership may move. `accept_sealed_ownership()` consumes
SEALED and atomically
returns `StagedArtifactV2(draft_ref, registration_ref)`, eliminating a circular
draft→registration seam. The mutually exclusive C2-build path instead consumes
the same SEALED reservation/seal/tag once through
`transfer_sealed_to_backend_transient()`, returning a store-issued backend
transient receipt; that reservation can never later enter direct artifact
acceptance. The build sink registers this receipt through the current
phase-bound scope and obtains the `PhaseBoundTransientRefV2` placed in
`C2ArtifactBuildOutput`. STAGED, TRANSFERRED and ABORTED are terminal; identical
digest replay returns the same receipt and every conflicting second terminal
path fails. Startup enumerates RESERVED/OPEN/SEALED records and bounded
`revoke_unconsumed()` first fences/quiesces any OPEN writer and handles
RESERVED|OPEN|SEALED before destroying the wrapping key/envelope; a crash before/after seal
cannot strand sensitive ciphertext. The domain-tagged helpers cover the exact
AAD, reservation, seal, abort, transfer and record field sets, excluding only
their own digest. Abort returns durable key-destruction/envelope-revocation
evidence. Chunk-boundary/golden, crash-window, replay and registration-failure
tests prove streaming, recovery and one-shot behavior.
State/nullability is closed: RESERVED/OPEN have no terminal receipts; SEALED has
exactly one seal; STAGED has seal+staged artifact only; TRANSFERRED has
seal+transfer only; ABORTED has exactly the durable abort (plus a prior seal only
when sealing had completed). Stale open/seal revisions fail, while same-revision
same-digest replay returns the identical readback.
All six sensitive-artifact helpers use UTF-8 RFC-8785 with literal domains
`sensitive-artifact-aad/1.0`, `sensitive-artifact-reservation/1.0`,
`sensitive-artifact-seal/1.0`, `sensitive-artifact-abort/1.0`,
`sensitive-artifact-transfer/1.0` and
`sensitive-artifact-reservation-record/1.0`. Each hashes every exact DTO field
in declaration order after canonical object-key sorting and excludes only its
own digest field; the record includes all nested receipt digests and stable
reservation identity. Golden and single-field tamper vectors are normative.


Canonical copy pattern:

```python
lease = secret_value.acquire_single_use(consumer_id=request_id)
destination = ZeroizableDestinationBufferV2.allocate(lease.byte_length)
try:
    copied = lease.read_into(destination)
    with destination.borrow_writable_view() as view:
        encode_from_mutable_view(view[:copied])
finally:
    destination.zeroize_and_close()
    lease.close_and_zeroize()
```

Raw `bytearray`/`bytes` destinations are rejected by type and runtime checks.

Sensitive staging invariants:

```text
- plaintext is held only in `ZeroizableSensitiveBufferV2` backed by an owned
  `bytearray` or anonymous writable `mmap`; immutable bytes/str are forbidden;
- `OwnedZeroizableSensitiveBufferV2` and its lease are the sole production
  implementation; they release exported memoryviews, overwrite every owned byte,
  verify the owned region is zeroed, and only then release storage;
- `read_into()` accepts only `ZeroizableDestinationBufferV2`; caller code must use
  `try/finally` (or its context manager) and call `destination.zeroize_and_close()`
  as well as `lease.close_and_zeroize()` on success, error, timeout or cancellation;
- the contract makes no false claim about copies created by third-party/native libraries;
- executor normalization accepts only
  `type(handle) is OwnedSensitiveObservationHandleV2`, verifies its factory
  ID/provenance, schema ID, transaction ID, handle_id, item_count, total_bytes and
  recomputed keyed integrity tag (constant-time compare) before OPEN → STAGING; structural/custom Protocol
  objects fail;
- provider obtains the handle only through
  exact concrete `OwnedSensitiveObservationHandleFactoryV2.create_from_mutable()`;
  provider context types it by the narrow Protocol, while runtime normalization
  requires the final concrete factory/handle types and module-private token;
  factory and handle share the exact invocation phase-lease object;
  provider-visible creation requires ACTIVE and is denied in PENDING/REVOKED;
  after boundary revocation, only executor-owned `stage_into()` with the exact
  internal `SensitiveBatchStagingCapabilityV2` may consume an OPEN handle and it
  requires the lease to be REVOKED (proving provider code has ended); `clear()`
  remains idempotently allowed in every state; the core factory
  transfers into owned storage and overwrites the complete mutable source in
  `finally` under its state lock before returning;
- it acquires exactly one zeroizable buffer lease, constructs
  `ZeroizableSensitiveBatchStageRequestV2`, and calls only
  executor-internal `SensitiveBatchStagingCapabilityV2`; provider-visible
  `ProviderStagingFacade` has no sensitive-stage method;
- success performs STAGING → CONSUMED, returns a staged batch with the same
  schema/transaction/factory/identity/count/size/keyed integrity tag, and zeroizes/closes the
  buffer lease;
- any exception also zeroizes/closes the buffer and transitions to CLEARED;
- a second stage/consume fails closed;
- clear() is idempotent and exposes no reveal/read API.
```

Exact variants:

```python
@dataclass(frozen=True)
class OperationProviderResult:
    header: ProviderResultHeaderV2
    observations: tuple[StagedObservationV2, ...]
    effect_registration: ExternalEffectRegistrationResultV2 | None = None
    result_kind: Literal[ProviderResultKind.OPERATION] = field(default=ProviderResultKind.OPERATION, init=False)


@dataclass(frozen=True)
class ArtifactProviderResult:
    header: ProviderResultHeaderV2
    artifacts: tuple[StagedArtifactV2, ...]
    result_kind: Literal[ProviderResultKind.ARTIFACT] = field(default=ProviderResultKind.ARTIFACT, init=False)


@dataclass(frozen=True, repr=False)
class CredentialProviderResult:
    header: ProviderResultHeaderV2
    credential_batch: SensitiveBatchHandleV2 = field(repr=False, compare=False)
    result_kind: Literal[ProviderResultKind.CREDENTIAL] = field(default=ProviderResultKind.CREDENTIAL, init=False)


@dataclass(frozen=True)
class SessionProviderResult:
    header: ProviderResultHeaderV2
    session: ManagedResourceDraftRefV2
    observations: tuple[StagedObservationV2, ...] = ()
    result_kind: Literal[ProviderResultKind.SESSION] = field(default=ProviderResultKind.SESSION, init=False)


@dataclass(frozen=True)
class RouteProviderResult:
    header: ProviderResultHeaderV2
    route: ManagedResourceDraftRefV2
    observations: tuple[StagedObservationV2, ...] = ()
    result_kind: Literal[ProviderResultKind.ROUTE] = field(default=ProviderResultKind.ROUTE, init=False)


@dataclass(frozen=True)
class C2ProviderResult:
    header: ProviderResultHeaderV2
    resources: tuple[ManagedResourceDraftRefV2, ...]
    artifacts: tuple[StagedArtifactV2 | C2ArtifactStageReceiptV1, ...] = ()
    observations: tuple[StagedObservationV2, ...] = ()
    result_kind: Literal[ProviderResultKind.C2_RESOURCE] = field(default=ProviderResultKind.C2_RESOURCE, init=False)


@dataclass(frozen=True)
class CompositeProviderResult:
    header: ProviderResultHeaderV2
    child_action_id: str
    child_execution_id: str
    child_result_ref: ExecutionResultRefV2
    result_kind: Literal[ProviderResultKind.COMPOSITE] = field(default=ProviderResultKind.COMPOSITE, init=False)


@dataclass(frozen=True, repr=False)
class SensitiveProviderResult:
    header: ProviderResultHeaderV2
    sensitive_batch: SensitiveBatchHandleV2 = field(repr=False, compare=False)
    artifacts: tuple[StagedArtifactV2, ...] = ()
    result_kind: Literal[ProviderResultKind.SENSITIVE] = field(default=ProviderResultKind.SENSITIVE, init=False)


RemoteAuthProviderResultV2: TypeAlias = OperationProviderResult | SessionProviderResult

ProviderResult: TypeAlias = (
    OperationProviderResult
    | ArtifactProviderResult
    | CredentialProviderResult
    | SessionProviderResult
    | RouteProviderResult
    | C2ProviderResult
    | CompositeProviderResult
    | SensitiveProviderResult
)
```

Validation invariants:

```text
- header.provider_id equals the mounted provider implementation ID;
- header.duration_ms >= 0 and completed_at >= started_at;
- draft transaction_id equals the current restricted provider invocation context ID;
- SessionProviderResult requires resource_kind=SESSION;
- RouteProviderResult requires resource_kind=PIVOT_ROUTE;
- C2ProviderResult permits only C2_CHANNEL, C2_ENROLLMENT, C2_AGENT, C2_TASK or DEPLOYMENT;
- CompositeProviderResult contains only `child_action_id`, `child_execution_id` and `child_result_ref`; parent/graph IDs, approval state, lifecycle state and decision-trace refs belong only to `ActionExecutionReportV2`/decision trace;
- CredentialProviderResult and SensitiveProviderResult are never serialized;
- non-sensitive variants contain only JSON-safe headers and draft refs;
- sensitive handle identity/count/keyed integrity tag must match `SensitiveBatchHandleV2` exactly using constant-time comparison;
- executor normalization uses one core-owned `stage_into(...)` → internal
  `SensitiveBatchStagingCapabilityV2.stage_zeroizable_sensitive_batch(...)`
  transition and never exposes that capability to provider code or materializes
  immutable plaintext bytes;
- the zeroizable buffer is cleared on success and every failure path;
- result_kind and runtime dataclass type must match exactly;
- `ad_smbexec`, `ad_winrm_exec` and `ad_dcom_exec` require exactly one
  `OperationProviderResult.effect_registration` of kind REMOTE_OPERATION;
  all other v6 operation actions require it to be `None` unless their semantic
  binding explicitly names a terminal effect. For a deferred operation,
  `header.outcome=SUCCEEDED` means only that the closed plan was validated and
  staged; final SUCCEEDED/PARTIAL publication additionally requires the
  coordinator's confirmed-effect receipt;
- unknown fields/variants and a result contract not allowed by §2.4 fail closed;
```

Outcome normalization is one closed policy table:

| Provider outcome | Execution status | Commit eligible |
|---|---|---|
| `SUCCEEDED` | `SUCCEEDED` | yes |
| `PARTIAL` with `PartialCommitPolicyV2.decide(snapshot=partial_policy, action_id=..., result_kind=..., reason_codes=...)==ACCEPT` | `PARTIAL` | yes |
| `PARTIAL` otherwise | `FAILED` | no |
| `FAILED` | `FAILED` | no |
| `UNAVAILABLE` | `UNAVAILABLE` | no |
| `TIMED_OUT` | `TIMED_OUT` | no |
| `CANCELLED` | `CANCELLED` | no |

`PartialCommitPolicyV2` is a closed action/result/reason-code registry owned by
PR-7. Before normalization the executor resolves
`registry.require_current(action_id)`; normalizer recomputes the schema-tagged
digest (excluding its own field), rejects duplicate/conflicting action/result/
reason rules, calls its own injected policy object, then
`registry.assert_current()` immediately before committing the normalization.
Provider/request-supplied, stale or forged snapshots and unknown reason codes
deny. Only the two commit-eligible rows may register
execution-result/audit publication participants or enter coordinator prepare.

`ProviderResultSchemaRegistry` is keyed by the exact table in §2.4. For
`RemoteAuthProviderResultV2` it permits only the two listed variants; all other
rows permit exactly one variant.

```python
@dataclass(frozen=True)
class ProviderResultPublicationBindingV2:
    action_id: str
    result_schema_id: str
    allowed_result_kinds: tuple[ProviderResultKind, ...]
    allowed_runtime_type_ids: tuple[str, ...]
    projector_id: str
    binding_digest: str


@dataclass(frozen=True)
class TransactionDraftRegistrationBindingV2:
    draft_ref: ParticipantDraftRefV2
    registration_ref: ParticipantRegistrationRefV2
    payload_schema_id: str
    payload_digest: str
    prepare_depends_on: tuple[ParticipantRegistrationRefV2, ...]
    commit_depends_on: tuple[ParticipantRegistrationRefV2, ...]


@dataclass(frozen=True)
class TransactionStagingSnapshotV2:
    transaction_id: str
    draft_registration_bindings: tuple[TransactionDraftRegistrationBindingV2, ...]
    staging_revision: int
    snapshot_digest: str


@runtime_checkable
class ProviderResultSchemaRegistry(Protocol):
    def require_publication_binding(
        self,
        *,
        action_id: str,
        result_schema_id: str,
    ) -> ProviderResultPublicationBindingV2: ...


@runtime_checkable
class ProviderResultProjectorV2(Protocol):
    def project(
        self,
        *,
        binding: ProviderResultPublicationBindingV2,
        provider_result: ProviderResult,
        verified_view: ProviderResultReadViewV2,
        staging_snapshot: TransactionStagingSnapshotV2,
        staged_audit: StagedAuditOutboxV2,
        staged_trace: StagedDecisionTraceV2,
        normalization: ProviderOutcomeNormalizationV2,
    ) -> NormalizedExecutionResultDraftV2: ...
```

The registry canonical-digests and validates the exact §2.4 mapping before any
sensitive handle consumption or publication. The sole executor-owned projector
uses exhaustive `match` plus `assert_never`: operation observations become
observation drafts; artifact receipts become artifact drafts; session/route/C2
receipts become their managed-resource drafts; credential/sensitive handles must
already be executor-staged sensitive drafts; composite contributes exactly its
verified `child_result_ref`; audit/trace are always the executor-staged refs.
It derives the exact one-to-one registration dependency set from
the executor-only `TransactionDraftRegistrationBindingV2` tuple, whose digest
covers each exact draft/registration identity and both phased edge sets. This
internal snapshot is not the narrow provider verification view. The projector
rejects an unregistered/extra/multiply-bound draft or stale
snapshot, constructs no new store ref, and computes the normalized draft digest.
RemoteAuth accepts only its operation/session variants; any runtime type/kind/
schema/projector mismatch fails before `ExecutionResultStore.stage()`.

PR-2 already owns `ExecutionResultV2`, `CleanupSummaryV2` and
`ActionExecutionReportV2`. PR-7 adds publication logic from committed draft
refs into that existing schema; it does not recreate those classes.

Remove generic `test_provider_result_is_json_safe`. Replace it with:

```text
test_non_sensitive_provider_results_are_json_safe
test_sensitive_provider_result_is_not_serializable
test_sensitive_provider_result_repr_is_redacted
test_sensitive_provider_result_only_reaches_transaction_participant
test_sensitive_handle_consumes_for_staging_exactly_once
test_sensitive_handle_second_consume_is_rejected
test_sensitive_handle_consumed_transaction_matches_invocation
test_sensitive_handle_clear_is_idempotent
test_sensitive_handle_has_no_reveal_api
```

18. Catalog сохраняет:
    ```text
    116 identities
    96 V1 adapters
    20 V2 provider identities
    ```
19. По мере mount конкретной identity legacy manual adapter заменяется одним V2 adapter owner без alias collision.
20. Добавить exhaustive API-version dispatch; неизвестная версия fail closed.

## Acceptance

```text
96 existing adapters не требуют signature rewrite
V1 check/execute/verify/cleanup regression-green
20 provider identities могут мигрировать на V2 по одной
каждая V2 identity имеет один зарегистрированный result_schema_id из §2.4
result schema registry валидирует exact (action_id, result_schema_id, allowed result variant) binding
all ProviderResult variants and support DTO have exact frozen fields
V2 sensitive/artifact/resource result is invisible before global commit
committed ExecutionResultV2 has no cleanup field; cleanup is post-commit finalization
нет direct V2 sensitive_ingestor.ingest
V2 material недоступен V1 adapter
одна identity имеет один active adapter owner
```

## Тесты

```text
test_existing_96_adapters_keep_v1_api
test_catalog_identity_count_unchanged
test_catalog_v1_v2_counts
test_v1_check_execute_verify_cleanup_unchanged
test_v2_protocol_does_not_inherit_v1
test_v2_adapter_not_required_to_implement_v1_methods
test_v1_and_v2_dispatch_are_disjoint
test_v2_executor_uses_execute_bound
test_v2_execute_bound_receives_one_invocation_context
test_v2_adapter_receives_only_transaction_id_and_restricted_facades_through_context
test_unknown_adapter_api_version_denied
test_result_schema_registry_has_20_entries
test_result_schema_matrix_matches_registry
test_each_v2_action_has_registered_result_schema
test_each_provider_result_variant_has_exact_fields
test_provider_result_kind_matches_runtime_variant
test_remote_auth_result_contract_accepts_only_operation_or_session
test_unknown_result_schema_id_denied
test_result_schema_id_mismatch_denied
test_duplicate_result_schema_registration_denied
test_remote_auth_result_allows_only_operation_or_session
test_artifact_provider_result_has_artifacts_tuple_and_no_ticket_ref
test_composite_provider_result_has_only_canonical_child_fields
test_composite_result_excludes_approval_lifecycle_and_trace
test_v1_executor_never_builds_material_bundle
test_v2_executor_never_calls_legacy_cleanup
test_v2_required_check_missing_fails_catalog
test_v2_required_verify_missing_fails_catalog
test_v2_check_runs_before_attempt_reservation
test_v2_check_failure_consumes_zero_approval_uses
test_v2_verify_receives_no_staging_or_participant_facade
test_v2_verify_cannot_publish_resource
test_provider_result_read_view_contains_typed_drafts_and_registration_views
test_provider_result_read_view_contains_no_live_handle_or_payload
test_v2_verify_failure_prevents_result_commit
test_router_required_check_and_verify_missing_fail_catalog
test_router_invoked_only_through_provider_call_boundary
test_router_boundary_enforces_timeout_cancellation_and_output_budget
test_cached_child_execution_facade_fails_after_route_returns
test_router_cannot_construct_or_supply_child_bridge
test_child_execution_spec_input_schema_must_match_selected_child
test_bound_material_bundle_not_constructible_from_request
test_sensitive_result_staged_in_execution_transaction
test_v2_path_has_no_direct_sensitive_ingest
test_non_sensitive_provider_results_are_json_safe
test_sensitive_provider_result_is_not_serializable
test_sensitive_provider_result_repr_is_redacted
test_sensitive_provider_result_only_reaches_transaction_participant
test_raw_backend_result_requires_decoder
test_artifact_refs_invisible_before_commit
test_credential_refs_invisible_before_commit
test_managed_resource_invisible_before_commit
test_execution_result_v2_published_only_after_commit
test_execution_result_ref_created_by_result_store_participant
test_composite_child_result_ref_requires_committed_child_result
test_bound_adapter_registers_transient_cleanup
test_bound_adapter_cannot_resolve_reference_outside_executor
test_single_adapter_owner_per_identity
test_composite_handoff_recovers_each_pending_reserve_intent_custody_progress_crash_gap
test_intent_and_pending_reconcilers_cannot_double_claim_parent_custody
test_outer_finally_skips_parent_owners_only_after_custody_transferred_readback
test_composite_cancel_or_revocation_waits_for_child_terminal_containment
test_nested_graph_non_owner_custody_never_closes_shared_graph
test_composite_stale_claim_fence_and_completion_or_failure_replay_are_idempotent
```

---

## Обязательный gate перед PR-8

PR-8 нельзя начинать, пока не выполнено:

```text
PR-1 canonical state ownership green
PR-2 ingress/approval/manual/stage gates green
PR-3 pre-call readiness recheck green
PR-4 trusted facts/targets/atomic checkout green
PR-5 finally + common execution transaction green
PR-6 closed DTO/task/build schemas green
PR-7 V1 compatibility + V2 transaction integration green
```

# PR-8. Подключение `payload_keying`

## Цель

Перевести `payload_keying` с manual placeholder на concrete mounted typed provider.

## MODIFY

```text
core/actions/adapters_evasion.py
modules/evasion/payload_keying.py
core/actions/catalog.py
core/actions/provider_mounts.py
core/actions/input_contracts.py
core/actions/provider_results.py
core/artifacts.py
tests/test_action_adapters_new.py
tests/test_high_risk_action_contracts.py
tests/test_payload_support_coverage.py
tests/test_runtime_plugin_catalog_contract.py
```

## CREATE

```text
core/providers/payload_keying.py
tests/test_payload_keying_provider.py
tests/integration/test_payload_keying_provider_e2e.py
```

## Реализация

1. Из `modules/evasion/payload_keying.py` выделить pure backend:
   ```python
   @dataclass(frozen=True)
   class PayloadTargetMetadata:
       target_os: C2TargetOS
       target_arch: C2TargetArch
       hostname: str | None
       username: str | None
       mac_address: str | None
       machine_id: str | None
       metadata_revision: int


   @dataclass(frozen=True, repr=False)
   class PayloadKeyingBackendResult:
       encrypted_payload: BackendOwnedTransientReceiptV2 = field(repr=False, compare=False)
       loader: BackendOwnedTransientReceiptV2 = field(repr=False, compare=False)
       encrypted_payload_digest: str
       loader_digest: str
       profile_id: PayloadKeyingProfileId


   def key_payload(
       payload: BoundNonSensitiveArtifactMaterial,
       profile: PayloadKeyingProfileId,
       target_metadata: PayloadTargetMetadata,
   ) -> PayloadKeyingBackendResult: ...
   ```
   These exact types are owned once by `core/providers/payload_keying.py`;
   The adapter registers both receipts through `invocation.scope`, receives
   `PhaseBoundTransientRefV2` values, and stages their IDs. Raw
   `TransientResource` never crosses a backend DTO. Neither result exposes a
   local output path.
2. Удалить provider-owned arbitrary `output_path`.
3. `PayloadKeyingAdapter` наследовать от `ArtifactBoundActionAdapter`.
4. Input — только `PayloadKeyingInputV2`.
5. Executor разрешает:
   ```text
   payload artifact snapshot
   target metadata snapshot
   authorization snapshots
   ```
6. После final authorization:
   ```text
   BoundNonSensitiveArtifactMaterial → phase-bound bounded stream into reviewed backend
   ```
7. Backend returns only two store-issued `BackendOwnedTransientReceiptV2`
   values plus public non-sensitive digests; it never returns bytes, paths or
   raw transient objects.
8. Adapter регистрирует:
   ```text
   encrypted payload artifact
   loader artifact
   ```
9. После успешной регистрации artifacts promotion не требуется, так как `ArtifactStore` уже владеет копиями.
10. Temporary buffers/files are owned and closed through `invocation.scope`; artifact drafts are created only through `invocation.staging`.
11. `ProviderMountSpec.mounted=true` выставить только в финальном commit PR.
12. Generic plugin raw execution для этой identity не использовать.

## Acceptance

```text
mount_spec.configured=true
mount_spec.mounted=true
mount_spec.typed_action_supported=true
descriptor.manual_gate=true
mount_spec.raw_command_supported=false
readiness checks cryptography import
ExecutionResult содержит только artifact refs
нет loader/payload contents в stdout/metadata
```

## Обязательные тесты

```text
test_payload_keying_hostname_profile
test_payload_keying_multi_profile
test_payload_keying_missing_target_metadata
test_payload_keying_payload_acl_mismatch
test_payload_keying_cross_mission_denied
test_payload_keying_revision_change_denied
test_payload_keying_provider_exception_cleanup
test_payload_keying_cancellation_cleanup
test_payload_keying_result_contains_refs_only
test_payload_keying_raw_dispatch_requires_typed_action
test_payload_keying_catalog_has_single_owner
test_payload_keying_readiness_missing_cryptography
test_payload_keying_e2e_artifacts_reopen_and_verify_digest
```

## Definition of done

```text
1/20 mounted
старый placeholder удалён для payload_keying
все unit/contract/integration tests green
```

---

# PR-9. Подключение Kerberos providers

## Цель

Подключить:

```text
kerberos_extract_tickets
kerberos_crack_tickets
```

## MODIFY

```text
core/actions/adapters_kerberos.py
core/killchain/ad/kerberos.py
core/actions/input_contracts.py
core/actions/provider_mounts.py
core/actions/readiness_probes.py
core/actions/provider_results.py
core/artifacts.py
core/credentials.py
core/ai/sensitive_ingestor.py
requirements/external-tools.txt
requirements/locks/manifest.json
requirements/locks/linux-x86_64/cp310/{external-tools,full}.txt
requirements/locks/linux-x86_64/cp311/{external-tools,full}.txt
requirements/locks/linux-x86_64/cp312/{external-tools,full}.txt
tests/test_action_adapters_new.py
tests/test_high_risk_action_contracts.py
tests/test_architecture_ratchet.py
```

## CREATE

```text
core/providers/kerberos.py
tests/test_kerberos_extract_provider.py
tests/test_kerberos_crack_provider.py
tests/integration/test_kerberos_provider_e2e.py
```

## `kerberos_extract_tickets`

### Реализация

1. Adapter наследуется от `CredentialBoundActionAdapter`.
2. Input — `KerberosExtractInputV2`.
3. Readiness проверяет нужные Impacket imports.
4. Executor разрешает credential metadata + ACL.
5. Material раскрывается только после final authorization.
6. Refactor existing backend:
   - не использовать глобальный loot directory как результат;
   - принимать scoped output directory from `invocation.scope`;
   - возвращать typed `KerberosExtractBackendResult`;
   - не возвращать credential material в text.
   Exact owner in `core/providers/kerberos.py`:
   ```python
   @dataclass(frozen=True, repr=False)
   class KerberosExtractBackendResult:
       ticket_artifact: BackendOwnedTransientReceiptV2 = field(repr=False, compare=False)
       artifact_size: int
       media_type: Literal["application/x-krb5-ccache"]
       target: str
   ```
   The adapter registers the receipt, receives a phase-bound transient ref and
   stages it with `SensitiveArtifactStageRequestV2(expected_size=...)`. The
   store computes keyed integrity and sealed-envelope digest; no plaintext
   ticket digest, path or bytes are serializable/repr-visible.
7. Полученный `.ccache` зарегистрировать в `ArtifactStore` как:
   ```text
   artifact_kind=KERBEROS_TICKET
   sensitive=true
   mission_id=context.mission_id
   owner_subject_id=context.subject_id
   ```
8. Temporary backend files удаляются в `finally`.
9. Adapter stages the ticket through `invocation.staging`, obtains `ticket_draft_ref: ArtifactDraftRefV2` and returns exactly:
   ```python
   ArtifactProviderResult(
       header=header,
       artifacts=(staged_ticket,),
   )
   ```
   Public `ticket://` ref appears only in committed `ExecutionResultV2`; no `ticket_ref` field exists on provider result.

### Acceptance

```text
ticket artifact имеет keyed integrity tag + sealed-record digest/ACL/revision,
но не unkeyed plaintext digest
temporary ccache удалён
provider available при Impacket imports
specific credential existence является request precondition
```

### Тесты

```text
test_extract_ticket_success_returns_ticket_ref
test_extract_ticket_unknown_credential_denied
test_extract_ticket_wrong_target_denied
test_extract_ticket_wrong_mission_denied
test_extract_ticket_backend_exception_cleanup
test_extract_ticket_timeout_cleanup
test_extract_ticket_cancellation_cleanup
test_extract_ticket_temp_file_removed
test_extract_ticket_plaintext_canary_absent
test_extract_ticket_returns_artifacts_tuple_without_ticket_ref_field
test_extract_ticket_readiness_missing_impacket
```

## `kerberos_crack_tickets`

### Реализация

1. Adapter наследуется от `ArtifactBoundActionAdapter`.
2. Input — `KerberosCrackInputV2`.
3. Executor разрешает ticket и wordlist snapshots.
4. Readiness expression:
   ```text
   hashcat OR john
   ```
5. Materialize ticket/wordlist через scoped temporary paths.
6. Direct `subprocess.run` заменить bounded process runner с:
   ```text
   process group
   timeout
   cancellation
   output limit
   finally termination
   ```
7. Parsed sensitive results are wrapped in one one-shot `SensitiveObservationHandleV2`; provider never calls `SecretStore`, `CredentialStore` or `SensitiveObservationIngestor` directly.
8. Return exact `CredentialProviderResult(header=header, credential_batch=batch_handle)`; after revoking the provider phase lease, executor calls `batch_handle.handle.stage_into(executor_sensitive_staging, ...)` exactly once with its private `SensitiveBatchStagingCapabilityV2`. It never reuses `invocation.staging`.
9. Committed `ExecutionResultV2` contains only credential refs/counts. Potfile/temp files are owned by `invocation.scope`.

### Acceptance

```text
hashcat/john readiness динамический
ticket/wordlist existence — request preconditions
credential plaintext отсутствует в output
process group завершается при timeout/cancel
```

### Тесты

```text
test_crack_uses_hashcat_when_available
test_crack_falls_back_to_john_before_attempt
test_crack_no_backend_is_unavailable
test_crack_ticket_acl_denied
test_crack_wordlist_acl_denied
test_crack_timeout_kills_process_group
test_crack_cancellation_kills_process_group
test_crack_exception_cleanup
test_crack_sensitive_results_become_credential_refs
test_crack_canary_absent_from_all_surfaces
test_crack_revision_change_denied
test_external_tools_requirement_change_regenerates_external_and_full_all_targets
test_lock_manifest_updated_for_external_tools_change
```

## Definition of done

```text
3/20 mounted
оба placeholders удалены
оба provider mount specs mounted=true
integration lane green
```

---

# PR-10. Подключение AD credential providers

## Цель

Подключить:

```text
ad_pass_the_ticket
pass_the_hash
ad_dump_lsass
ad_sam_dump
```

## MODIFY

```text
core/actions/adapters_ad_credential.py
core/killchain/ad/credential.py
core/actions/input_contracts.py
core/actions/operation_catalog.py
core/actions/provider_mounts.py
core/actions/readiness_probes.py
core/actions/provider_results.py
tests/test_action_adapters_new.py
tests/test_high_risk_action_contracts.py
tests/test_killchain_defensive_coverage.py
tests/test_credential_reference_boundary.py
tests/test_credentials_access_contracts.py
```

## CREATE

```text
core/providers/ad_credentials.py
tests/test_pass_the_ticket_provider.py
tests/test_pass_the_hash_provider.py
tests/test_lsass_dump_provider.py
tests/test_sam_dump_provider.py
tests/integration/test_ad_credential_providers_e2e.py
```

## Общая подготовка

1. Существующие `CredentialStore`, `CredentialRef` и legacy `CredentialMaterial`
   остаются только V1 compatibility implementation details. PR-10 не расширяет их
   как V2 public/provider API.
2. V2 credential adapters не импортируют и не вызывают:
   ```text
   CredentialStore
   CredentialMaterial
   material_for_execution()
   call_credential_provider()
   ```
3. Executor/PR-4 compatibility bridge атомарно checkout-ит credential reference и
   до provider invocation строит только `BoundCredentialMaterial` внутри
   `BoundProviderInvocationContext.materials`.
4. V2 backend получает `BoundCredentialMaterial` либо provider-specific
   single-use zeroizable lease, созданный из него внутри reviewed adapter;
   plaintext/hash не возвращается
   в adapter result и не переносится в argv/environment/log.
5. `BoundCredentialMaterial.secret` остаётся checkout-bound handle. Provider не
   может повторно разрешить credential ref или обратиться к global store.
6. Existing CLI credential fallbacks не используются в typed providers.
7. Backend exceptions преобразуются и redacted внутри `ProviderCallBoundary`, а
   material закрывается owning checkout/outer finally.

## `pass_the_hash`

### Реализация

1. Заменить существующий fail-closed stub concrete backend.
2. Input — `PassTheHashInputV2`.
3. Credential requirement:
   ```text
   auth_kind=nt_hash
   ```
4. Operation берётся из `RemoteExecOperationCatalog`.
5. Adapter извлекает exact `BoundCredentialMaterial` из `invocation.materials`, проверяет `auth_kind=NT_HASH` и передаёт backend только bounded NTLM view, target и compiled operation.
6. Raw hash не помещается в argv/environment/log, а backend не имеет доступа к `CredentialStore`.
7. Result имеет exact alias `RemoteAuthProviderResultV2`: `OperationProviderResult` без retained session либо `SessionProviderResult`, если backend создаёт retained authenticated session.
8. Если backend создаёт retained session:
   - register transient handle in `invocation.scope`;
   - call `invocation.staging.stage_managed_resource(...)`, which atomically transfers ownership and registers the participant;
   - return `SessionProviderResult(header=header, session=staged.resource_draft_ref)`;
   - activate the session only through final transaction commit;
   - on any pre-commit failure transaction rollback closes the handle.
9. Без retained session вернуть exact `OperationProviderResult`; обе variants входят только в `RemoteAuthProviderResultV2`.

### Acceptance

```text
stub удалён
nt_hash material не сериализуется
неверный auth_kind блокируется до provider
operation только из catalog
```

### Тесты

```text
test_pth_requires_nt_hash_auth_kind
test_pth_password_credential_rejected
test_pth_operation_catalog_only
test_pth_target_binding
test_pth_acl_binding
test_pth_backend_exception_cleanup
test_pth_timeout_cleanup
test_pth_cancellation_cleanup
test_pth_canary_hash_absent
test_pth_v2_does_not_import_credential_store_or_legacy_material
test_pth_receives_bound_credential_material_only
test_pth_session_promotion
test_pth_late_ingestion_failure_rolls_back_session
test_pth_result_draft_failure_rolls_back_session
```

## `ad_pass_the_ticket`

### Реализация

1. Input — `PassTheTicketInputV2`.
2. Adapter receives only executor-built `BoundSensitiveArtifactMaterial`
   constrained to `ArtifactKind.KERBEROS_TICKET`, acquires its phase-bound
   single-use zeroizable lease, and materializes a scoped `.ccache` only through
   the reviewed sensitive-temp sink/`invocation.scope`; direct `ArtifactStore`
   lookup and the stale `BoundArtifactMaterial` name are forbidden.
3. `KRB5CCNAME` устанавливается через scoped context manager.
4. Старое environment значение восстанавливается в `finally`.
5. Operation берётся из catalog.
6. Backend returns exact `RemoteAuthProviderResultV2`: normally `OperationProviderResult`, or `SessionProviderResult` only if a retained session is staged through `invocation.staging`.
7. Temporary ticket удаляется through `invocation.scope` in outer finally.

### Acceptance

```text
environment всегда восстановлен
temporary ticket всегда удалён
ticket ACL/revision проверяются
```

### Тесты

```text
test_ptt_success
test_ptt_missing_ticket
test_ptt_acl_denied
test_ptt_revision_change
test_ptt_environment_restored_on_success
test_ptt_environment_restored_on_exception
test_ptt_environment_restored_on_timeout
test_ptt_environment_restored_on_cancellation
test_ptt_temp_file_removed
test_ptt_receives_bound_artifact_material_only
test_ptt_v2_does_not_resolve_artifact_store_directly
test_ptt_returns_remote_auth_result_variant_only
```

## `ad_dump_lsass`

### Реализация

1. Input — `CredentialDumpInputV2`.
2. Readiness:
   ```text
   Impacket SMB/WMI provider
   optional pypykatz parser
   ```
3. Existing backend refactor:
   - consume only executor-built `BoundCredentialMaterial` from invocation context;
   - scoped output directory;
   - typed backend result;
   - remote temporary artifact tracked by `invocation.scope`;
   - remote delete callback registered до execution;
   - local dump staged through `invocation.staging`;
   - extracted credentials returned only through one-shot `SensitiveObservationHandleV2`; no direct `CredentialStore`/ingestor call.
4. Each dump is passed through `stage_artifact(SensitiveArtifactStageRequestV2)`;
   adapter returns exact `SensitiveProviderResult(header=header,
   sensitive_batch=batch_handle, artifacts=tuple(staged_artifacts))`.
5. Executor consumes/stages the one-shot sensitive handle through its internal `SensitiveBatchStagingCapabilityV2` after execute returns; cleanup executes even when download/parser/result normalization fails.

### Acceptance

```text
remote cleanup registered before dump attempt
local dump stored as sensitive artifact
plaintext credentials absent
parser optionality reflected in readiness/result
```

### Тесты

```text
test_lsass_success_artifact_and_refs
test_lsass_remote_cleanup_on_success
test_lsass_remote_cleanup_on_download_failure
test_lsass_cleanup_on_parser_exception
test_lsass_timeout_cleanup
test_lsass_cancellation_cleanup
test_lsass_pypykatz_unavailable_partial_result
test_lsass_canary_absent
test_lsass_acl_denied
test_lsass_v2_has_no_direct_credential_store_or_sensitive_ingestor_call
test_lsass_returns_exact_sensitive_provider_result
```

## `ad_sam_dump`

### Реализация

1. Input — `CredentialDumpInputV2`.
2. Consume only executor-built `BoundCredentialMaterial` and refactor existing backend to typed scoped output.
3. SAM/SYSTEM/SECURITY artifacts stage through `invocation.staging` as sensitive artifact drafts.
4. Extracted hashes return only as one-shot `SensitiveObservationHandleV2`; executor transaction performs credential/secret staging.
5. Return exact `SensitiveProviderResult(header=header,
   sensitive_batch=batch_handle, artifacts=tuple(staged_artifacts))`, where
   every item is the `StagedArtifactV2` returned by `stage_artifact()`.
6. Temporary files are owned by `invocation.scope`; V2 code never calls `CredentialStore` directly.

### Acceptance

```text
artifacts refs-only
hashes refs-only
no global loot dependency
```

### Тесты

```text
test_sam_dump_success
test_sam_dump_multiple_artifacts
test_sam_dump_no_output_failure
test_sam_dump_backend_exception_cleanup
test_sam_dump_timeout_cleanup
test_sam_dump_cancellation_cleanup
test_sam_dump_canary_absent
test_sam_dump_acl_denied
test_sam_dump_v2_has_no_direct_credential_store_or_sensitive_ingestor_call
test_sam_dump_returns_exact_sensitive_provider_result
```

## Definition of done

```text
7/20 mounted
четыре placeholders удалены
four-provider integration lane green
```

---

# PR-11. Подключение AD remote-execution leaf providers

## Цель

Подключить:

```text
ad_smbexec
ad_winrm_exec
ad_dcom_exec
```

## MODIFY

```text
core/actions/adapters_ad_lateral.py
core/killchain/ad/lateral.py
core/actions/input_contracts.py
core/actions/operation_catalog.py
core/actions/provider_mounts.py
core/actions/readiness_probes.py
core/actions/provider_results.py
core/credentials.py
tests/test_action_adapters_new.py
tests/test_high_risk_action_contracts.py
```

## CREATE

```text
core/execution/processes.py
core/execution/remote_operation_models.py
core/execution/remote_operation_store.py
core/execution/remote_operation_participant.py
core/providers/ad_lateral.py
core/providers/ad_lateral_backends.py
tests/test_ad_smbexec_provider.py
tests/test_ad_winrm_provider.py
tests/test_ad_dcom_provider.py
tests/integration/test_ad_remote_leaf_providers_e2e.py
tests/test_remote_operation_participant.py
tests/test_remote_operation_output_contract.py
tests/test_remote_operation_credential_resolver.py
```

## Общая реализация

1. Все adapters наследуются от `CredentialBoundActionAdapter`.
2. Input — `RemoteExecInputV2`.
3. Executor разрешает credential/ACL/preconditions.
4. Operation ID компилируется внутри provider-owned catalog.
5. Provider не принимает arbitrary command.
6. Existing provider functions refactor в backend classes used only by the
   executor-owned terminal effect participant:
   ```text
   SMBExecBackend
   WinRMBackend
   DCOMBackend
   ```
7. Backend injection используется в unit tests.
8. Credential-bearing CLI fallback не используется.
9. Each leaf stages one closed `RemoteOperationPlanV1`, registers
   `ExternalEffectKindV2.REMOTE_OPERATION`, and returns exact
   `OperationProviderResult(effect_registration=...)`; it never calls the
   backend. Retained session variants are not part of these result schemas.
10. Cancellation/timeout for dispatch/probe pass through the participant's
    bounded `ParticipantOperationContextV2`.
11. Any preflight transient registers in `invocation.scope`; observations stage
    only through `invocation.staging`. Backend-created effect transients are
    participant-owned and never re-enter provider code.

Exact PR-11 effect model:

```python
class RemoteOperationServiceV1(str, Enum):
    SMBEXEC = "smbexec"
    WINRM = "winrm"
    DCOM = "dcom"


class RemoteOperationAttemptStateV1(str, Enum):
    RESERVED = "reserved"
    DISPATCHING = "dispatching"
    CONFIRMED = "confirmed"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"
    RECONCILING = "reconciling"


@dataclass(frozen=True)
class RemoteOperationOutputReservationRefV1:
    reference: str
    transaction_id: str
    operation_id: RemoteExecOperationId
    output_schema_id: str
    reservation_revision: int
    reservation_digest: str


@dataclass(frozen=True)
class RemoteOperationPlanV1:
    transaction_id: str
    action_id: str
    target: str
    service: RemoteOperationServiceV1
    operation_id: str
    operation_payload_schema_id: str
    operation_payload_ref: ParticipantPayloadDraftRefV2
    output_reservation_ref: RemoteOperationOutputReservationRefV1
    credential_ref: str
    credential_revision: int
    attempt_id: str
    idempotency_key: str
    plan_digest: str


@dataclass(frozen=True)
class IdentityRemoteOperationOutputV1:
    principal_name: str
    domain_name: str | None
    machine_name: str


@dataclass(frozen=True)
class HostRemoteOperationOutputV1:
    hostname: str
    os_name: str
    os_version: str
    architecture: str


@dataclass(frozen=True)
class NetworkInterfaceOutputV1:
    name: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class NetworkRemoteOperationOutputV1:
    interfaces: tuple[NetworkInterfaceOutputV1, ...]
    routes: tuple[str, ...]
    connections: tuple[str, ...]


@dataclass(frozen=True)
class ServiceStatusOutputV1:
    service_name: str
    state: str
    start_mode: str | None


@dataclass(frozen=True)
class ServiceRemoteOperationOutputV1:
    services: tuple[ServiceStatusOutputV1, ...]


RemoteOperationOutputV1: TypeAlias = (
    IdentityRemoteOperationOutputV1
    | HostRemoteOperationOutputV1
    | NetworkRemoteOperationOutputV1
    | ServiceRemoteOperationOutputV1
)


@dataclass(frozen=True)
class RemoteOperationBackendRequestV1:
    attempt_id: str
    idempotency_key: str
    plan_ref: ParticipantPayloadDraftRefV2
    plan_digest: str
    absolute_deadline_monotonic: float


class RemoteOperationEffectDispositionV1(str, Enum):
    CONFIRMED = "confirmed"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class RemoteOperationEffectReceiptV1:
    transaction_id: str
    participant_id: str
    attempt_id: str
    plan_digest: str
    disposition: RemoteOperationEffectDispositionV1
    backend_receipt_ref: str | None
    output: RemoteOperationOutputV1 | None
    output_digest: str | None
    probe_token: str
    attempt_revision: int
    receipt_digest: str


@dataclass(frozen=True)
class RemoteOperationEffectProbeV1:
    transaction_id: str
    participant_id: str
    attempt_id: str
    disposition: RemoteOperationEffectDispositionV1
    backend_receipt_ref: str | None
    output: RemoteOperationOutputV1 | None
    output_digest: str | None
    attempt_revision: int
    probe_digest: str


@runtime_checkable
class RemoteOperationBackendV1(Protocol):
    def dispatch(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectReceiptV1: ...
    def probe(
        self,
        request: RemoteOperationBackendRequestV1,
    ) -> RemoteOperationEffectProbeV1: ...


@runtime_checkable
class RemoteOperationCredentialLeaseV1(Protocol):
    @property
    def lease_id(self) -> str: ...
    def transfer_to_protected_worker_channel(
        self,
        *,
        backend_request_digest: str,
    ) -> str: ...
    def close_and_zeroize(self) -> None: ...


@runtime_checkable
class RemoteOperationCredentialResolverV1(Protocol):
    def acquire(
        self,
        *,
        plan: RemoteOperationPlanV1,
        checkout_recovery_ref: CheckoutRecoveryRefV2,
        mission_id: str,
        subject_id: str,
        target: str,
        operation: ParticipantOperationContextV2,
        fence: ExecutionFinalizationFenceV2,
    ) -> RemoteOperationCredentialLeaseV1: ...


class RemoteOperationExternalEffectParticipant(ExecutionCommitParticipant):
    participant_id: str
    transaction_id: str
    participant_kind: Literal[ParticipantKindV2.EXTERNAL_EFFECT]
    effect_kind: Literal[ExternalEffectKindV2.REMOTE_OPERATION]

    def prepare(self, request: ParticipantPrepareRequestV2) -> ParticipantPrepareOutcomeV2: ...
    def commit(self, request: ParticipantCommitRequestV2) -> ParticipantCommitReceiptV2: ...
    def finalize_visibility(
        self,
        prepare_receipt: ParticipantPrepareReceiptV2,
        commit_receipt: ParticipantCommitReceiptV2,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantFinalizeReceiptV2: ...
    def rollback(
        self,
        receipt: ParticipantPrepareReceiptV2 | None,
        operation: ParticipantOperationContextV2,
    ) -> ParticipantRollbackReceiptV2: ...
    def reconcile(
        self,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantReconcileResultV2: ...
```

The provider canonical-encodes/stages the plan payload and registers the
terminal effect with identical reversible plan dependencies in both phased
sets and no managed-resource request. Before registration the executor asks the
remote-operation store to reserve the exact operation-catalog output schema and
puts its store-issued `RemoteOperationOutputReservationRefV1` in the plan; the
provider cannot write it. The result participant prepares before dispatch and
adds the terminal effect only to `commit_depends_on`.

The credential ref in the plan is never a secret-material lookup capability.
At dispatch the registry-injected participant uses only
`RemoteOperationCredentialResolverV1`, which reopens the exact checkout fence,
revalidates mission/action/subject/target/auth-kind/revision and returns one
operation-context/fence-bound zeroizable lease. That lease transfers through a
protected zeroizable worker channel and is wiped in the participant's `finally`;
neither the plan/journal nor restart probe serializes credential material, and
there is no global credential-store fallback.

The attempt store has a UNIQUE key on
`(transaction_id, participant_id, attempt_id)` and persists RESERVED then
DISPATCHING before any backend call. CONFIRMED forces COMMIT_DECIDED;
FAILED_NO_EFFECT chooses ABORT_DECIDED; timeout/ambiguous return persists
UNKNOWN and coordinator IN_DOUBT. Recovery invokes probe only and never repeats
dispatch. Registry mapping is exact:
`REMOTE_OPERATION + RemoteOperationPlanV1 ->
RemoteOperationExternalEffectParticipant`.

Every inventory operation is data-producing, not ack-only. A CONFIRMED receipt
or confirming probe must carry the exact output variant selected by
`operation_id`, within catalog byte/item/string limits, plus its canonical
digest; FAILED_NO_EFFECT/UNKNOWN require both output fields null. Before
returning CONFIRMED the participant validates the closed output, atomically
fills the preallocated transaction-hidden reservation, and records its digest.
Its hidden commit receipt emits exactly one
`ResolvedDraftReferenceV2(source_draft_type=EXTERNAL_EFFECT_OUTPUT, ...)` mapping
to normalized FACT refs (and a bounded ARTIFACT ref only where the catalog
explicitly declares one). The execution-result participant obtains those refs
from its effect commit dependency. No observation/fact participant prepares
after dispatch, provider code is never re-entered, and a probe replay must yield
the identical output digest or enter failed reconciliation.

## `ad_smbexec`

Readiness:

```text
Impacket SMBExec importable
required provider version supported
```

Request preconditions:

```text
confirmed_ad_access
smb_service_available
credential target/service binding
```

Тесты:

```text
test_smbexec_success
test_smbexec_missing_service_fact
test_smbexec_wrong_credential_service
test_smbexec_operation_catalog_only
test_smbexec_backend_exception_cleanup
test_smbexec_timeout_cleanup
test_smbexec_cancellation_cleanup
test_smbexec_canary_absent
test_smbexec_readiness_missing_impacket
test_ad_remote_leaf_result_is_operation_provider_result
```

## `ad_winrm_exec`

Readiness:

```text
pywinrm importable
supported transport version
```

Request preconditions:

```text
confirmed_ad_access
winrm_service_available
```

Тесты:

```text
test_winrm_success
test_winrm_http_endpoint
test_winrm_https_endpoint
test_winrm_missing_service_fact
test_winrm_backend_exception_cleanup
test_winrm_timeout_cleanup
test_winrm_cancellation_cleanup
test_winrm_canary_absent
test_winrm_readiness_missing_pywinrm
```

## `ad_dcom_exec`

Readiness:

```text
Impacket DCOM backend importable
```

Request preconditions:

```text
confirmed_ad_access
dcom_service_available
```

Тесты:

```text
test_dcom_success
test_dcom_missing_service_fact
test_dcom_backend_exception_cleanup
test_dcom_timeout_cleanup
test_dcom_cancellation_cleanup
test_dcom_operation_catalog_only
test_dcom_canary_absent
test_dcom_readiness_missing_impacket
```

## Acceptance

```text
все три mounted=true
нет arbitrary command
нет CLI credential fallback
каждый leaf имеет отдельный readiness probe
```

## Definition of done

```text
10/20 mounted
leaf integration lane green
```

---

# PR-12. Подключение `ad_remote_execution` composite router

## Цель

Подключить `ad_remote_execution` как selection-only composite router с child `ActionExecutor` re-entry и единым ingress-bound approval execution lease.

## CREATE

```text
tests/test_ad_remote_execution_router.py
tests/test_router_reentry_contract.py
tests/integration/test_ad_remote_execution_router_e2e.py
```

## MODIFY

```text
core/actions/adapters_ad_lateral.py
core/actions/composite_execution.py
core/actions/selection.py
core/actions/executor.py
core/actions/provider_results.py
core/actions/provider_mounts.py
core/actions/target_extraction.py
core/auth/approval_leases.py
core/ai/planner.py
core/ai/pipeline_planning.py
tests/test_action_adapters_new.py
tests/test_high_risk_action_contracts.py
```

## Canonical execution classification

```text
execution_node_kind=COMPOSITE_ROUTER
provider_transport=CHILD_EXECUTOR
```

## Реализация

1. Adapter implements `TypedCompositeRouterV2` with mandatory read-only
   `check_bound`, `route_bound` and `verify_bound`; it does not inherit the leaf
   `TypedActionAdapterV2.execute_bound` surface.
2. Input — `RemoteExecInputV2`.
3. Adapter не импортирует:
   ```text
   core.killchain.ad.lateral
   concrete AD provider backends
   credential/material resolvers
   ```
4. Parent executor:
   ```text
   checks out authenticated ingress
   derives principal
   resolves mission
   resolves approval execution lease
   decodes trusted service facts
   extracts target
   runs router readiness
   authorizes parent action/stage
   opens no material and creates no approval attempt/provider staging context
   ```
5. Parent selection consumes zero approval uses.
6. Selector candidates:
   ```text
   ad_smbexec
   ad_winrm_exec
   ad_dcom_exec
   ```
7. До concrete attempt можно исключить candidate по:
   ```text
   unconfigured
   unmounted
   unavailable
   missing trusted service precondition
   operation unsupported by leaf
   ```
8. Exclusion before attempt consumes zero approval uses.
9. Selector chooses exactly one leaf before child execution.
   Router invokes it only through
   `context.child_execution.run_selected_child(spec=ChildExecutionSpecV2(...))`.
10. Router supplies only selected action, closed `RemoteExecInputV2` and optional
    derived idempotency key. The executor facade creates the child request ID,
    inherits mission/approval/fact refs, narrows budget/lineage, derives the
    `ChildIngressLease` and constructs the private `ChildExecutionBridge`.
11. The executor-created child `ActionRequestV2` contains only canonical fields:
    ```text
    new request_id
    same mission_ref
    same approval_ref
    same precondition_fact_refs
    derived child idempotency key when required
    child-specific closed RemoteExecInputV2 carrying target/credential/operation
    ```
    `parent_execution_id` is forbidden in `ActionRequestV2`; it exists only in
    executor-owned `ExecutionLineage` and `ChildExecutionBridge`. Before any
    child lookup/authorization, `_run_v2_internal` enforces all §4.8A identity
    equalities.
12. Internal non-serializable `ChildExecutionBridge`:
    ```text
    derived ChildIngressLease bound to child request_id, parent execution ID and execution graph
    same execution_graph_id
    same approval_graph_lease; child receives its own ApprovalAttemptLease only after leaf selection
    selected child action ID
    ```
13. Router/caller/planner cannot create, receive or serialize the bridge.
14. Parent does not pass child:
    ```text
    principal/mission/approval snapshots
    fact snapshots
    reference snapshots
    mount/readiness snapshots
    material bundle
    authorization decision
    ```
15. Child executor re-runs:
    ```text
    canonical state lookup
    ingress checkout
    principal derivation
    mission/approval resolution
    parent-child approval graph validation
    trusted fact decode
    target extraction
    credential ACL checkout
    child readiness
    child stage/manual policy
    atomic snapshot/reference checkout
    side-effect-free check_bound
    reserve_attempt → PENDING
    immediate readiness recheck
    material open only after successful recheck
    release_before_start on unavailable, otherwise atomic start
    provider invocation
    transaction/finally lifecycle
    ```
15. Approval graph must permit:
    ```text
    parent action=ad_remote_execution
    selected child action
    parent/child lateral_movement stage
    operation ID
    target
    credential capability
    ```
16. Use semantics:
    ```text
    parent selection → 0 uses
    child denial/unavailable before attempt → 0 uses
    selected child reserve_attempt → start → exactly 1 use
    ```
17. With `max_uses=1`, the execution graph can begin at most one concrete child attempt.
18. Child cannot mint a new lease or larger use budget.
19. After provider attempt begins, no automatic fallback to another active leaf.
20. Provider failure/timeout/cancellation after attempt consumes the use.
21. Result — exact `CompositeProviderResult`:
    ```text
    child_action_id
    child_execution_id
    child_result_ref
    ```
    Parent execution/graph IDs, approval attempt/use state, child lifecycle and decision-trace refs stay only in `ActionExecutionReportV2`, `ExecutionLineage` and decision trace.
22. `mounted=true` only after all router/re-entry tests pass.

## Acceptance

```text
execution_node_kind=COMPOSITE_ROUTER
provider_transport=CHILD_EXECUTOR
no direct leaf/backend/material call
principal authority derives from a child-bound ChildIngressLease over the same validated ingress session
parent consumes zero approval uses
selected child consumes exactly one use
child independently revalidates facts/targets/ACL/readiness/policy
no active fallback after attempt
```

## Тесты

```text
test_ad_router_selects_smb
test_ad_router_selects_winrm
test_ad_router_selects_dcom
test_ad_router_skips_unavailable_leaf_before_attempt
test_ad_router_skips_missing_service_precondition_before_attempt
test_ad_router_child_reenters_executor
test_ad_router_bridge_not_serializable
test_ad_router_child_uses_derived_child_ingress_lease
test_ad_router_child_re_resolves_principal_from_ingress
test_ad_router_child_shares_approval_graph_not_attempt_lease
test_ad_router_child_cannot_mint_approval_budget
test_ad_router_parent_consumes_zero_approval_uses
test_ad_router_child_consumes_one_approval_use
test_ad_router_max_uses_one_blocks_second_child_attempt
test_ad_router_denied_before_attempt_consumes_zero_uses
test_ad_router_unavailable_before_attempt_consumes_zero_uses
test_ad_router_failure_after_attempt_consumes_use
test_ad_router_child_redecodes_facts
test_ad_router_child_reextracts_targets
test_ad_router_child_re_resolves_acl
test_ad_router_child_has_new_request_id
test_ad_router_action_argument_request_bridge_ids_must_match
test_ad_router_request_id_must_match_child_lease
test_ad_router_lineage_ids_must_match_child_lease
test_ad_router_identity_mismatch_fails_before_approval_or_provider
test_ad_router_parent_approval_without_child_permission_denied
test_ad_router_child_permission_without_parent_graph_permission_denied
test_ad_router_no_direct_leaf_call
test_ad_router_no_direct_backend_import
test_ad_router_no_fallback_after_attempt
test_ad_router_preserves_parent_child_trace
test_ad_router_child_denial_propagates
test_ad_router_composite_result_has_only_canonical_fields
```

## Definition of done

```text
11/20 mounted
router ingress/approval re-entry E2E green
```

---
# PR-13. Подключение Pivot providers

## Цель

Подключить:

```text
pivot_remote_forward
pivot_ssh_chain
pivot_proxy_scan
```

## MODIFY

```text
core/actions/adapters_pivot.py
core/killchain/pivot.py
core/actions/input_contracts.py
core/actions/provider_mounts.py
core/actions/readiness_probes.py
core/actions/provider_results.py
core/sessions.py
core/pivot_routes.py
core/credentials.py
tests/test_pivot_coverage.py
tests/test_action_adapters_new.py
tests/test_high_risk_action_contracts.py
```

## CREATE

```text
core/providers/pivot.py
tests/test_pivot_remote_forward_provider.py
tests/test_pivot_ssh_chain_provider.py
tests/test_pivot_proxy_scan_provider.py
tests/integration/test_pivot_providers_e2e.py
```

## `pivot_remote_forward`

### Реализация

1. Adapter наследуется от `SessionBoundActionAdapter`.
2. Input — `RemoteForwardInputV2`.
3. Executor разрешает session metadata/ACL.
4. Проверяет request targets:
   ```text
   SSH target
   destination_host
   callback/listen endpoint
   ```
5. После final authorization получает live session.
6. Existing backend refactor:
   - не использовать ambient SSH handle;
   - возвращать typed tunnel handle;
   - register close callback in `invocation.scope`.
7. Call `invocation.staging.stage_managed_resource(...)`; the facade atomically transfers the tunnel, registers its internal participant and returns `StagedManagedResourceV2`.
8. Return exact `RouteProviderResult(header=header, route=staged.resource_draft_ref)`.
9. The executor owns sensitive/result preparation and final transaction commit.
10. При любой ошибке до durable commit decision coordinator rollback закрывает tunnel и удаляет PENDING route.

### Acceptance

```text
route остаётся active после action
generic cleanup route не закрывает
explicit route close работает
destination scope проверяется
```

### Тесты

```text
test_remote_forward_success_returns_route_ref
test_remote_forward_session_missing
test_remote_forward_session_acl_denied
test_remote_forward_destination_out_of_scope
test_remote_forward_invalid_ports
test_remote_forward_registration_failure_closes_tunnel
test_remote_forward_exception_closes_tunnel
test_remote_forward_timeout_cleanup
test_remote_forward_cancellation_cleanup
test_remote_forward_promoted_route_survives
test_remote_forward_late_ingestion_failure_rolls_back_route
test_remote_forward_result_draft_failure_rolls_back_route
```

## `pivot_ssh_chain`

### Реализация

1. Input — `SSHChainInputV2`.
2. Readiness:
   ```text
   paramiko importable
   ```
3. Executor разрешает каждый credential reference отдельно.
4. Проверяет каждый hop target в scope.
5. Material каждого hop раскрывается только на время connect.
6. Existing `create_ssh_chain` refactor:
   - typed hop material;
   - no plaintext hop dict;
   - no `AutoAddPolicy` без отдельной host-key policy configuration;
   - typed final session handle.
7. До завершения chain все созданные clients принадлежат `invocation.scope`.
8. Stage the final chain with `invocation.staging.stage_managed_resource(...)`; the facade atomically transfers ownership, registers the internal participant and returns `StagedManagedResourceV2`.
9. Return exact `SessionProviderResult(header=header, session=staged.resource_draft_ref)`.
10. The executor owns sensitive/result preparation and final transaction commit.
11. При failure/late error transaction rollback and `invocation.scope` close all uncommitted hops.

### Acceptance

```text
никаких plaintext hop lists
каждый hop имеет ACL/target binding
final session retained
partial chain всегда закрывается
```

### Тесты

```text
test_ssh_chain_success_returns_session_ref
test_ssh_chain_empty_rejected
test_ssh_chain_max_hops_enforced
test_ssh_chain_hop_out_of_scope
test_ssh_chain_wrong_credential_target
test_ssh_chain_second_hop_failure_closes_first
test_ssh_chain_registration_failure_closes_all
test_ssh_chain_timeout_cleanup
test_ssh_chain_cancellation_cleanup
test_ssh_chain_promoted_session_survives
test_ssh_chain_late_ingestion_failure_rolls_back_session
test_ssh_chain_result_draft_failure_rolls_back_session
test_ssh_chain_host_key_policy_required
```

## `pivot_proxy_scan`

### Реализация

1. Adapter наследуется от `PivotRouteBoundActionAdapter`.
2. Input — `PivotProxyScanInputV2`.
3. Proxy endpoint берётся только из `PivotRouteStore`.
4. Route state и authorization revision проверяются.
5. Target/ports/timeouts bounded.
6. Existing backend refactor на injectable scanner backend.
7. Process/network resources регистрируются в invocation scope.
8. Result — exact `OperationProviderResult` with transaction-owned observation drafts.

### Acceptance

```text
planner не передаёт proxy port
route existence является request precondition
provider readiness не зависит от конкретного route
```

### Тесты

```text
test_proxy_scan_success
test_proxy_scan_route_missing
test_proxy_scan_route_closed
test_proxy_scan_route_acl_denied
test_proxy_scan_target_out_of_route_scope
test_proxy_scan_port_limit
test_proxy_scan_timeout_cleanup
test_proxy_scan_cancellation_cleanup
test_proxy_scan_route_revision_change
test_proxy_scan_readiness_without_pysocks_or_proxychains
```

## Definition of done

```text
14/20 mounted
pivot lifecycle E2E green
retained session/route tests green
```

---

# PR-14. Единый C2ControlClient, static service identity и result-control semantics

## Цель

Создать единственный outbound control IPC path, привязать OS peer к operator/RBAC, сделать idempotency атомарной с side effects, заменить destructive result read и подготовить control plane для следующих C2 provider PR.

Этот PR не монтирует C2 providers и не меняет agent task wire. Provider count остаётся `14/20`.

## CREATE

```text
core/c2/client.py
core/c2/control_protocol.py
core/c2/control_models.py
core/c2/control_auth.py
core/c2/control_signing.py
core/c2/control_signing_keyring.py
core/c2/resource_participant.py
core/c2/resource_participant_models.py
core/c2/resource_payload_registry.py
core/c2/control_peer.py
core/c2/control_idempotency.py
core/c2/control_commands.py
core/c2/control_transactions.py
core/c2/control_audit.py
core/c2/control_rbac.py
core/c2/result_service.py
core/c2/result_models.py
core/c2/application_service.py
core/c2/grant_service.py
core/c2/bootstrap.py
core/c2/service_identity.py
core/c2/control_server_identity.py
scripts/install_c2_service_identity.py
scripts/bootstrap_c2_admin.py
data/octopus-c2.socket
data/octopus-c2.sysusers
data/octopus-c2.tmpfiles
data/octopus-c2.env.example
tests/test_c2_control_client.py
tests/test_c2_control_protocol.py
tests/test_c2_control_signing.py
tests/test_c2_control_signing_rotation.py
tests/test_c2_peer_auth.py
tests/test_c2_operator_rbac_binding.py
tests/test_c2_idempotency.py
tests/test_c2_control_transactions.py
tests/test_c2_daemon_resource_participant.py
tests/test_c2_resource_visibility_fence.py
tests/test_c2_resource_participant.py
tests/test_c2_audit_redaction.py
tests/test_c2_result_semantics.py
tests/test_c2_result_ack_models.py
tests/test_c2_application_service.py
tests/test_c2_grant_service.py
tests/test_c2_admin_bootstrap.py
tests/test_c2_service_identity.py
tests/test_c2_control_server_identity.py
tests/integration/test_c2_socket_activation_identity_e2e.py
tests/integration/test_c2_systemd_socket_activation_e2e.py
tests/test_single_c2_ipc_path.py
tests/test_cli_c2_action_routing.py
```

## MODIFY

```text
core/c2/daemon.py
core/c2/operators.py
core/c2/db_backend.py
core/c2/event_store.py
core/c2/protocol.py
core/cli/application.py
core/cli/main.py
core/secrets.py
config.py
config.yaml
.env.example
data/octopus-c2.service
setup.py
pyproject.toml
MANIFEST.in
README.md
docs/architecture/contracts-and-ownership.md
docs/architecture/current-system-map.md
tests/test_c2_daemon_coverage.py
tests/test_c2_security.py
tests/test_c2_reliability_components.py
tests/test_cli_application_menus_coverage.py
tests/test_packaging_contract.py
```

## 14.1. Separate control protocol

```text
C2_CONTROL_PROTOCOL_VERSION = "1.0"
```

Agent protocol remains independently versioned. Каждый control message использует
ровно один framing format:

```text
4-byte unsigned big-endian length prefix
followed by canonical UTF-8 JSON
```

Одна connection содержит ровно один **control exchange**, состоящий ровно из
четырёх framed messages:

```text
1. CLIENT_HELLO
2. SERVER_CHALLENGE
3. AUTHENTICATED_CONTROL_REQUEST
4. CONTROL_RESPONSE
```

Нормативная формулировка — `one control exchange per connection`.
Frames 1–2 являются authentication handshake; frames 3–4 являются единственной
application request/response pair внутри этого exchange.

После четвёртого frame обе стороны закрывают connection. Keep-alive, pipelining,
несколько control requests на одной connection, двух-frame shortcut и
дополнительный unframed traffic запрещены. Reject zero, oversized, truncated,
out-of-order and trailing frames. Enforce connect/read/write deadlines and
cumulative byte limits на весь four-frame exchange.

`core/c2/control_protocol.py` owns the streaming seam used by secret-bearing
subcodecs:

```python
@runtime_checkable
class BoundedFrameReaderV1(Protocol):
    @property
    def remaining_bytes(self) -> int: ...
    def read_exact_into(
        self,
        destination: ZeroizableDestinationBufferV2,
        *,
        byte_count: int,
    ) -> None: ...
    def require_eof(self) -> None: ...
```

The concrete reader is created only after length/deadline/cumulative-budget
validation and never offers `read() -> bytes` for a secret segment.

## 14.2. Static service identity and socket activation


Production identity:

```text
User=octopus-c2
Group=octopus-c2
SupplementaryGroups=octopus-c2-clients
DynamicUser запрещён
```

Создать:

```text
data/octopus-c2.socket
```

Socket unit:

```text
ListenStream=/run/octopus/octopus-c2.sock
SocketUser=octopus-c2
SocketGroup=octopus-c2-clients
SocketMode=0660
RemoveOnStop=true
```

tmpfiles contract:

```text
/run/octopus
owner=octopus-c2
group=octopus-c2-clients
mode=0750
```

Service принимает systemd-provided listening FD и не создаёт второй socket path.

State directory:

```text
owner=octopus-c2
group=octopus-c2
mode=0700
```

Control-server identity:

```text
private key:
    /var/lib/octopus/control-identity/server-ed25519.key
    owner=octopus-c2
    group=octopus-c2
    mode=0600

pinned public key:
    /etc/octopus/control-server-ed25519.pub
    owner=root
    group=root
    mode=0644
```

`scripts/install_c2_service_identity.py` создаёт unique per-install Ed25519 keypair, устанавливает root-owned public pin и никогда не печатает private key.

Packaging обязан включать:

```text
data/octopus-c2.service
data/octopus-c2.socket
data/octopus-c2.sysusers
data/octopus-c2.tmpfiles
```

Старый assertion `DynamicUser=yes` заменить на static identity, socket unit, runtime-directory traversal, control-server identity paths и packaged-file assertions.

## 14.3. Peer authentication under systemd socket activation

Для systemd-created listener client-side `SO_PEERCRED` нельзя использовать как доказательство daemon UID/PID. Credentials AF_UNIX peer фиксируются при `connect(2)`, `listen(2)` или `socketpair(2)`; listener создаёт и переводит в listen systemd, а daemon получает FD позже.

Canonical split:

```text
server authenticates client:
    SO_PEERCRED on each accepted connected socket
    peer PID/UID/GID never taken from payload

client authenticates daemon:
    filesystem socket metadata
    root-owned pinned Ed25519 public key
    signed pre-authentication challenge
```

Client checks before connect:

```text
socket path is not symlink
path is AF_UNIX socket
socket owner/group/mode match socket unit
parent directory owner/group/mode match profile
socket st_dev/st_ino captured for handshake binding
```

The four-frame exchange performs server authentication before API key disclosure:

```text
Frame 1 — CLIENT_HELLO:
    protocol version
    random client_nonce

Frame 2 — SERVER_CHALLENGE:
    daemon_instance_id
    random server_nonce
    listener st_dev/st_ino
    host boot_id
    Ed25519 signature over the domain-separated transcript

Client verifies:
    pinned root-owned public key
    protocol version
    listener inode/device against pre-connect stat
    transcript signature

Frame 3 — AUTHENTICATED_CONTROL_REQUEST:
    operator authentication
    mission/subject binding
    one typed control request

Frame 4 — CONTROL_RESPONSE:
    one typed response bound to request_id and transcript
```

API key or any secret-bearing field must not be serialized before successful
Frame-2 verification.

`SO_PEERCRED` observed by the client may be recorded only as diagnostic activator metadata and must not be compared to expected daemon UID/PID under socket activation.

Daemon startup requirements:

```text
adopt exactly one systemd listening FD
fstat inherited listener
load private identity key
fail closed if key/public pin binding is invalid
never bind a second control socket
```

Server-side accepted connection requirements:

```text
getsockopt(SO_PEERCRED)
allowed client UID/GID check
operator API-key authentication
subject/mission/RBAC binding
```

Integration tests:

```text
test_fd_activation_harness_proves_client_peercred_is_activator_not_daemon
test_signed_server_handshake_succeeds_with_inherited_listener
test_signed_server_handshake_rejects_wrong_pinned_key
test_signed_server_handshake_rejects_listener_inode_mismatch
test_api_key_not_sent_before_server_identity_verified
test_server_validates_client_so_peercred_on_accepted_socket
test_systemd_socket_activation_e2e_signed_server_identity
test_daemon_adopts_one_fd_and_never_rebinds_path
```

## 14.4. Operator/RBAC binding and exact control principal

PR-14 owns the exact peer/operator/control-auth models in
`core/c2/control_auth.py` and `core/c2/control_peer.py`:

```python
class OperatorRole(str, Enum):
    ADMIN = "admin"
    OPERATOR = "operator"
    READONLY = "readonly"


@dataclass(frozen=True)
class PeerPrincipal:
    pid: int
    uid: int
    gid: int


@dataclass(frozen=True)
class AuthenticatedOperator:
    operator_id: str
    subject_id: str
    name: str
    role: OperatorRole
    active: bool
    authorization_revision: int
    allowed_peer_uids: tuple[int, ...]
    allowed_peer_gids: tuple[int, ...]


@dataclass(frozen=True)
class AuthenticatedControlPrincipal:
    operator_id: str
    subject_id: str
    role: OperatorRole
    peer: PeerPrincipal
    mission_id: str
    operator_revision: int
    peer_binding_revision: int
    mission_grant_revision: int
    authenticated_at: float
    expires_at: float
```

`AuthenticatedControlPrincipal` is constructed only after API-key verification,
peer UID/GID binding, active operator check, subject binding, mission grant and
RBAC authorization. Request-supplied role/name/operator ID is rejected.

PR-14 imports the sole `SecretValue` protocol from `core.secrets.py`, created in
PR-5. It does not define a second secret capability. Control encoders acquire one
zeroizable lease, serialize into a bounded frame and clear the lease in
`finally`.

## 14.4A. Root-owned first-admin bootstrap и grant lifecycle

Удалить automatic/default-admin creation из `OperatorManager` initialization.
Production daemon никогда не создаёт администратора сам и не пишет bootstrap key
из service process.

Создать root-only offline command:

```text
octopus-c2-bootstrap-admin
```

Контракт:

```text
- effective UID обязан быть 0;
- daemon должен быть остановлен либо DB открыта под exclusive bootstrap lock;
- command разрешён только когда active ADMIN operators отсутствуют;
- создаёт первый ADMIN operator и стабильный subject_id;
- создаёт initial peer binding для явно переданных client UID/GID;
- создаёт или verifies canonical system control mission `system://c2-control`;
- выдаёт первому ADMIN grant только на `system://c2-control`, без implicit grants на operational missions;
- API key is published once at `/root/.config/octopus/c2-bootstrap-admin.key`, mode 0600, and never printed;
- key publication is crash-safe: create a same-directory `O_CREAT|O_EXCL` temp file mode 0600, write/fsync it, commit ADMIN + `bootstrap_admin_transactions(PENDING, key_digest, temp_name)` under the exclusive DB lock, atomically rename to the final path, fsync the directory, then mark the journal COMMITTED;
- restart with a PENDING journal must verify temp/final file digest and finish rename/commit idempotently; it must not create a second ADMIN or a second key;
- if DB commit exists but neither matching temp nor final key file exists, bootstrap enters `RECOVERY_REQUIRED` and fails closed; root-only offline key rotation/recovery is required;
- повторный bootstrap после появления ADMIN fail closed, except idempotent recovery of the same PENDING journal;
- bootstrap API не публикуется через Unix control socket.
```

После bootstrap изменения bindings/grants выполняет только authenticated
`C2ApplicationService` через ADMIN-only operations:

```text
SYNC_OPERATOR_PEER_BINDINGS
REVOKE_OPERATOR_PEER_BINDING
SYNC_OPERATOR_MISSION_GRANTS
REVOKE_OPERATOR_MISSION_GRANT
```

Sync/revoke используют revision compare-and-swap, idempotency и audit. Revocation:

```text
- увеличивает authorization_revision;
- инвалидирует cached principal/grant snapshots;
- запрещает новые ingress leases и child leases;
- обнаруживается executor fencing перед provider call;
- не возвращает уже STARTED approval use.
```

Tests:

```text
test_operator_manager_does_not_auto_create_admin
test_root_bootstrap_requires_uid_zero
test_root_bootstrap_creates_first_admin_peer_and_system_control_grant
test_root_bootstrap_does_not_grant_operational_missions
test_root_bootstrap_key_file_is_root_owned_0600
test_bootstrap_key_publication_fsyncs_file_and_directory
test_bootstrap_crash_after_db_commit_finishes_pending_rename
test_bootstrap_pending_recovery_never_creates_second_admin
test_bootstrap_missing_key_material_enters_recovery_required
test_second_bootstrap_is_rejected
test_bootstrap_not_exposed_over_control_socket
test_admin_sync_peer_bindings_revisioned
test_admin_revoke_peer_binding_invalidates_new_ingress
test_admin_sync_mission_grants_revisioned
test_admin_revoke_mission_grant_invalidates_child_reentry
```

## 14.5. Closed control-operation and RBAC matrix

The single owner is `core/c2/control_commands.py` (PR-14):

```python
class C2ControlActionV1(str, Enum):
    PING = "ping"
    VERSION = "version"
    READINESS = "readiness"
    LIST_AGENTS = "list_agents"
    LIST_RESULTS = "list_results"
    ACK_RESULTS = "ack_results"
    PURGE_RESULTS = "purge_results"
    MANAGE_OPERATORS_LIST = "manage_operators_list"
    MANAGE_OPERATORS_CREATE = "manage_operators_create"
    MANAGE_OPERATORS_DEACTIVATE = "manage_operators_deactivate"
    MANAGE_OPERATORS_ROTATE = "manage_operators_rotate"
    SYNC_OPERATOR_PEER_BINDINGS = "sync_operator_peer_bindings"
    REVOKE_OPERATOR_PEER_BINDING = "revoke_operator_peer_binding"
    SYNC_OPERATOR_MISSION_GRANTS = "sync_operator_mission_grants"
    REVOKE_OPERATOR_MISSION_GRANT = "revoke_operator_mission_grant"
    RESERVE_ENROLLMENT_FOR_BUILD = "reserve_enrollment_for_build"
    CHECKOUT_ENROLLMENT_BUILD_MATERIAL = "checkout_enrollment_build_material"
    RELEASE_ENROLLMENT_BUILD_RESERVATION = "release_enrollment_build_reservation"
    QUERY_ENROLLMENT_BUILD_RESERVATION = "query_enrollment_build_reservation"
    PREPARE_ENROLLMENT_DEPLOYMENT = "prepare_enrollment_deployment"
    COMMIT_ENROLLMENT_DEPLOYMENT = "commit_enrollment_deployment"
    FINALIZE_ENROLLMENT_DEPLOYMENT = "finalize_enrollment_deployment"
    ABORT_ENROLLMENT_DEPLOYMENT = "abort_enrollment_deployment"
    QUERY_ENROLLMENT_DEPLOYMENT = "query_enrollment_deployment"
    REVOKE_ENROLLMENT = "revoke_enrollment"
    PREPARE_C2_RESOURCE = "prepare_c2_resource"
    COMMIT_C2_RESOURCE = "commit_c2_resource"
    FINALIZE_C2_RESOURCE_VISIBILITY = "finalize_c2_resource_visibility"
    ABORT_C2_RESOURCE = "abort_c2_resource"
    QUERY_C2_RESOURCE = "query_c2_resource"
    CANCEL_TASK = "cancel_task"
    CLEANUP_DAEMON_RESOURCE = "cleanup_daemon_resource"
    REGISTER_DEPLOYMENT_MIRROR = "register_deployment_mirror"
```

The direct operational commands below are removed from the canonical control
catalog and may exist only as rejected migration aliases:

```text
ISSUE_ENROLLMENT
QUEUE_TYPED_TASK
CREATE_DNS_CHANNEL
```

Those resources are created exclusively by `PREPARE_C2_RESOURCE` inside the
executor-owned participant lifecycle.

RBAC:

| Action group | ADMIN | OPERATOR | READONLY |
|---|---:|---:|---:|
| PING/VERSION/READINESS | yes | yes | yes |
| LIST_AGENTS/LIST_RESULTS | yes | yes | yes |
| ACK_RESULTS | yes | yes | no |
| PURGE_RESULTS | yes | no | no |
| MANAGE_OPERATORS_* | yes | no | no |
| SYNC/REVOKE operator peer/mission grants | yes | no | no |
| enrollment build/deployment lifecycle | yes | yes | no |
| PREPARE/COMMIT/FINALIZE/ABORT/QUERY C2 resource | yes | yes | no |
| CANCEL_TASK/CLEANUP_DAEMON_RESOURCE | yes | yes | no |
| REGISTER_DEPLOYMENT_MIRROR | yes | yes | no |

Every mutation also checks mission/resource ACL, subject binding, target scope,
idempotency and the local execution-transaction binding. Participant commands
cannot be invoked through `C2ApplicationService`; only the executor-owned
participant implementation can call them.

API key/RBAC alone never authorizes participant lifecycle commands. PR-14 owns
the generic signed authorization and request/response envelope without importing
PR-15 payload types:

```python
@dataclass(frozen=True)
class ParticipantControlAuthorizationV1:
    key_id: str
    transaction_id: str
    participant_id: str
    mission_id: str
    subject_id: str
    action_id: str
    coordinator_revision: int
    request_digest: str
    expires_at: float
    nonce: str
    signature: str


@dataclass(frozen=True)
class ExecutionControlAuthorizationV1:
    """Pre-participant executor authority for enrollment build checkout only."""

    key_id: str
    transaction_id: str
    request_id: str
    mission_id: str
    subject_id: str
    action_id: Literal["c2:c2_deploy"]
    coordinator_revision: int
    request_digest: str
    expires_at: float
    nonce: str
    signature: str


@dataclass(frozen=True)
class ParticipantControlRequestV1:
    action: C2ControlActionV1
    authorization: ParticipantControlAuthorizationV1
    payload_schema_id: str
    payload_digest: str
    canonical_payload_b64u: str = field(repr=False, compare=False)
    prior_receipt_ref: str | None = None
    prior_receipt_digest: str | None = None
    expected_resource_revision: int | None = None


@dataclass(frozen=True)
class ParticipantControlReceiptV1:
    transaction_id: str
    participant_id: str
    action: C2ControlActionV1
    resource_ref: str | None
    resource_revision: int | None
    receipt_ref: str
    receipt_digest: str
    daemon_instance_id: str
    result_payload_schema_id: str | None
    result_payload_digest: str | None
    result_payload_b64u: str | None = field(repr=False, compare=False)


class ParticipantControlPhaseV1(str, Enum):
    PENDING = "pending"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED_VISIBLE = "finalized_visible"
    ABORTED = "aborted"
    FAILED = "failed"


@dataclass(frozen=True)
class ParticipantControlQuerySnapshotV1:
    transaction_id: str
    participant_id: str
    resource_ref: str | None
    resource_revision: int | None
    phase: ParticipantControlPhaseV1
    receipt_ref: str | None
    receipt_digest: str | None
    snapshot_digest: str
    result_payload_schema_id: str | None
    result_payload_digest: str | None
    result_payload_b64u: str | None = field(repr=False, compare=False)


class C2ControlErrorCodeV1(str, Enum):
    MALFORMED = "malformed"
    NOT_AUTHORIZED = "not_authorized"
    IDEMPOTENCY_CONFLICT = "idempotency_conflict"
    WRONG_PHASE = "wrong_phase"
    REPLAY = "replay"
    UNAVAILABLE = "unavailable"
    INTERNAL_FAILURE = "internal_failure"


@dataclass(frozen=True)
class BoundedControlErrorV1:
    reason_code: C2ControlErrorCodeV1
    retryable: bool
    detail_ref: str | None


ParticipantControlResponseV1: TypeAlias = (
    ParticipantControlReceiptV1 | ParticipantControlQuerySnapshotV1 | BoundedControlErrorV1
)


@runtime_checkable
class ParticipantControlSignerV1(Protocol):
    def sign_participant_request(
        self,
        unsigned_request: ParticipantControlRequestV1,
    ) -> ParticipantControlRequestV1: ...

    def sign_execution_request(
        self,
        *,
        action: C2ControlActionV1,
        authorization: ExecutionControlAuthorizationV1,
        payload_schema_id: str,
        payload_digest: str,
    ) -> ExecutionControlAuthorizationV1: ...


@runtime_checkable
class ParticipantControlVerifierV1(Protocol):
    def verify_participant_request(
        self,
        request: ParticipantControlRequestV1,
    ) -> None: ...

    def verify_execution_request(
        self,
        *,
        action: C2ControlActionV1,
        authorization: ExecutionControlAuthorizationV1,
        payload_schema_id: str,
        payload_digest: str,
    ) -> None: ...
```

Wire bodies are canonical unpadded base64url strings. Decoders reject padding,
non-canonical alphabet, invalid UTF-8 JSON, duplicate keys and decoded bodies
above `C2_CONTROL_MAX_PAYLOAD_BYTES=1_048_576`; IDs/strings are at most 256/4096
UTF-8 bytes, nesting at most 16 and a frame at most 2_097_152 bytes. Digests are
over decoded RFC-8785 canonical JSON bytes, never over base64 text.

PR-14 owns a separate executor signing key and daemon public-key pin, not an API
key. The key ID, public key, validity interval and rotation predecessor are held
in a root-owned keyring; daemon startup rejects an unpinned or overlapping key
set. Rotation installs the new public pin before switching the signer and keeps
the predecessor only through the maximum request expiry. The domain-separated
signature transcript is:

```text
OCTOPUS-C2-PARTICIPANT-V1 || action || every authorization field except signature
|| payload_schema_id || decoded canonical payload digest
|| prior receipt ref/digest || expected resource revision
```

The execution-control transcript uses domain
`OCTOPUS-C2-EXECUTION-CHECKOUT-V1` and binds the same request/action/payload
fields without a participant ID. Daemon nonce consumption is one durable CAS
keyed by `(key_id, nonce, transaction_id, action)` and occurs in the same local
transaction as phase validation. The daemon verifies signature, expiry, nonce
replay, transaction/participant/mission/subject/action/revision binding,
request/payload/prior-receipt digests and phase CAS.

`ExecutionControlAuthorizationV1` is accepted only for the four enrollment build
RESERVE/CHECKOUT/RELEASE/QUERY actions, only on the executor-owned checkout
client. It never authorizes participant lifecycle, cleanup or task cancellation.
Conversely, `CLEANUP_DAEMON_RESOURCE` and participant-driven `CANCEL_TASK` always
require `ParticipantControlAuthorizationV1`; API key/RBAC is insufficient.
PR-16/PR-17 register kind-specific payload decoders; unknown schema/phase fails
closed. Tests cover replay, expired/bad signature, wrong participant/action/
revision, key rotation, request/payload digest and prior-receipt mismatch.

## 14.6. Mission/subject-bound idempotency

Durable key:

```text
UNIQUE(operator_id, subject_id, mission_id, action, idempotency_key)
UNIQUE(operator_id, request_id)
```

Digest includes:

```text
operator ID
subject ID
mission ID
action
payload schema version
canonical payload digest
```

Same key with different binding returns `idempotency_conflict`.

DB-only operations use one SQLite transaction for reservation + side effect + audit/outbox + committed response.

External side effects use durable `PENDING` command journal before side effect and startup reconciliation after crash.

## 14.6A. Generic cross-process C2 resource participant and visibility fence

PR-14 creates generic cross-process infrastructure only. It does not import
`AgentTaskEnvelopeV12` or any PR-15 enrollment/task wire model.

```python
class C2DaemonResourceKindV1(str, Enum):
    ENROLLMENT = "enrollment"
    TASK = "task"
    DNS_CHANNEL = "dns_channel"


class C2DaemonResourceStateV1(str, Enum):
    PENDING = "pending"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED_VISIBLE = "finalized_visible"
    ABORTED = "aborted"
    FAILED = "failed"


@dataclass(frozen=True)
class C2DaemonResourceControlPayloadV1:
    resource_kind: C2DaemonResourceKindV1
    payload_schema_id: str
    payload_digest: str
    canonical_payload: bytes = field(repr=False, compare=False)


@dataclass(frozen=True)
class C2DaemonResourcePrepareReceiptV1:
    transaction_id: str
    participant_id: str
    daemon_instance_id: str
    resource_ref: str
    resource_revision: int
    resource_kind: C2DaemonResourceKindV1
    payload_digest: str
    receipt_digest: str
    state: Literal[C2DaemonResourceStateV1.PENDING]


@dataclass(frozen=True)
class C2DaemonResourceCommitReceiptV1:
    transaction_id: str
    participant_id: str
    resource_ref: str
    resource_revision: int
    commit_digest: str
    state: Literal[C2DaemonResourceStateV1.COMMITTED_HIDDEN]


@dataclass(frozen=True)
class C2DaemonResourceFinalizeReceiptV1:
    transaction_id: str
    participant_id: str
    resource_ref: str
    resource_revision: int
    visibility_digest: str
    finalized_at: float
    state: Literal[C2DaemonResourceStateV1.FINALIZED_VISIBLE]
```

The concrete participant is owned only by `core/c2/resource_participant.py`:

```python
class C2DaemonResourceParticipant(ExecutionCommitParticipant):
    participant_id: str
    transaction_id: str
    participant_kind: Literal[ParticipantKindV2.CROSS_PROCESS_RESOURCE]

    def prepare(
        self,
        request: ParticipantPrepareRequestV2,
    ) -> ParticipantPrepareOutcomeV2: ...

    def commit(
        self,
        request: ParticipantCommitRequestV2,
    ) -> ParticipantCommitReceiptV2: ...

    def finalize_visibility(
        self,
        prepare_receipt: ParticipantPrepareReceiptV2,
        commit_receipt: ParticipantCommitReceiptV2,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantFinalizeReceiptV2: ...

    def rollback(
        self,
        receipt: ParticipantPrepareReceiptV2 | None,
        operation: ParticipantOperationContextV2,
    ) -> ParticipantRollbackReceiptV2: ...

    def reconcile(
        self,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantReconcileResultV2: ...
```

The implementation resolves the transaction-bound participant payload from the
local participant store, invokes exactly one of the closed control operations,
persists the corresponding typed C2 receipt, and returns only the generic
coordinator receipt that references that persisted typed receipt. It cannot be
constructed or called by a provider or `C2ApplicationService`.

Exact control protocol:

```text
PREPARE_C2_RESOURCE
    validate exact payload schema through daemon registry;
    reserve idempotency;
    create PENDING enrollment/task/channel;
    for DNS synchronously create/bind a non-serving socket; do not start the
    receive loop, parse/respond to packets, or emit observations/tasks;
    return prepare receipt.

COMMIT_C2_RESOURCE
    persist the semantic commit as COMMITTED_HIDDEN;
    ordinary agent/control lookup still filters the resource;
    return hidden-commit receipt.

FINALIZE_C2_RESOURCE_VISIBILITY
    require the exact transaction/participant/prepare/commit receipts;
    move enrollment→ISSUED or task→QUEUED; for DNS start the receive loop, pass
    a running/health barrier, then move channel→ACTIVE;
    return finalization ACK.

ABORT_C2_RESOURCE
    revoke/cancel/close a PENDING resource idempotently.

QUERY_C2_RESOURCE
    return exact PENDING/COMMITTED_HIDDEN/FINALIZED_VISIBLE/ABORTED/FAILED state
    without repeating resource creation or bind.
```

Before DNS finalize, packets receive no response and create no facts/tasks. If a
gated loop is required by the platform it must drop all traffic and emit nothing
until the finalization gate opens. Abort before `COMMIT_DECIDED` closes the bound
socket. This—not lookup filtering—is the visibility guarantee.

The provider stages `C2DaemonResourceControlPayloadV1` as a bounded participant
payload and registers `CrossProcessResourceParticipantRegistrationPayloadV2`.
The one `register()` result is
`CrossProcessResourceRegistrationResultV2`, containing both the registration
ref and local `ManagedResourceDraftRefV2`. `C2ProviderResult` uses that draft.

`ExecutionCommitCoordinator` is the only caller of participant prepare, hidden
commit, visibility finalization, abort and reconcile. There is no direct
`ISSUE_ENROLLMENT`, `QUEUE_TYPED_TASK` or `CREATE_DNS_CHANNEL` call before
participant registration, so a resource cannot be created twice.

Cross-process registration uses `DeferredManagedResourceRequestV2`, never a
`ManagedResourceStageRequestV2` with a fake transient ID. Registration
preallocates the transaction-private managed draft; participant prepare attaches
the daemon ref. Exact kind mapping is:

```text
C2_ENROLLMENT ↔ ENROLLMENT
C2_TASK       ↔ TASK
C2_CHANNEL    ↔ DNS_CHANNEL
DEPLOYMENT    ↔ external effect DEPLOYMENT_START
```

PR-16 registers exact daemon payload decoders for enrollment and V12 task after
PR-15 models exist. PR-17 registers the DNS payload decoder. PR-14 itself owns
only the generic payload envelope/registry and therefore type-checks without
PR-15.

Visibility contract:

```text
daemon PREPARE        → PENDING, hidden
daemon COMMIT         → COMMITTED_HIDDEN
coordinator COMMIT_APPLIED
coordinator FINALIZING_VISIBILITY
daemon FINALIZE ACK   → visible resource
coordinator COMMITTED → local refs/result visible
```

No simultaneous cross-process ACID claim is made. A crash after daemon finalize
but before local `COMMITTED` is roll-forward only: `QUERY_C2_RESOURCE` proves the
finalized resource and the coordinator writes its final marker. Local success
is never published before the daemon finalization ACK.

Required tests:

```text
test_pr14_c2_participant_has_no_pr15_import
test_c2_daemon_resource_participant_implements_exact_commit_protocol
test_provider_cannot_construct_or_call_c2_daemon_resource_participant
test_c2_control_catalog_contains_prepare_commit_finalize_abort_query
test_enrollment_control_catalog_contains_prepare_commit_finalize_abort_query
test_direct_issue_queue_create_commands_are_not_canonical
test_c2_prepare_creates_one_pending_resource
test_c2_commit_keeps_resource_hidden
test_c2_finalize_ack_precedes_local_result_publication
test_c2_abort_closes_pending_resource
test_c2_query_reconciles_without_repeating_effect
test_dns_is_not_created_before_participant_prepare
test_c2_registration_returns_one_closed_cross_process_result
test_crash_after_daemon_finalize_rolls_local_coordinator_forward
test_participant_control_requires_signed_transaction_binding
test_participant_control_replay_expired_wrong_phase_and_wrong_id_denied
test_release_and_query_enrollment_build_reservation_are_closed_commands
test_api_key_rbac_alone_cannot_invoke_participant_lifecycle
```

## 14.7. Mission-scoped non-destructive result lifecycle

ACL обязателен для read и mutation operations. Task delivery acknowledgement и
operator acknowledgement результатов — разные протоколы и разные durable models.

Agent-wire delivery receipt uses the single canonical `AgentTaskDeliveryAckV12`
definition from PR-15 §15.2. PR-14 does not define a parallel agent-wire DTO.

Control-plane result acknowledgement:

```python
@dataclass(frozen=True)
class ResultAckSelectionV1:
    result_ref: str
    expected_revision: int


@dataclass(frozen=True)
class ResultAckRequestV1:
    mission_id: str
    agent_ref: str
    selections: tuple[ResultAckSelectionV1, ...]


@dataclass(frozen=True)
class ResultAcknowledgementRecordV1:
    result_ref: str
    result_revision: int
    acknowledged_by_subject_id: str
    acknowledged_at: float
    acknowledgement_revision: int
```

`ACK_RESULTS` принимает только `ResultAckRequestV1`. Он не принимает и не
переиспользует `AgentTaskDeliveryAckV12`, task delivery attempt или beacon ACK.

Canonical signatures:

```python
class C2ControlResultServiceV1(Protocol):
    def list_agents(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> AgentPageV1: ...

    def list_results(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        agent_ref: str,
        *,
        cursor: str | None,
        limit: int,
    ) -> ResultPageV1: ...

    def ack_results(
        self,
        principal: AuthenticatedControlPrincipal,
        request: ResultAckRequestV1,
    ) -> ResultAckBatchV1: ...

    def purge_results(
        self,
        principal: AuthenticatedControlPrincipal,
        mission_id: str,
        *,
        before: float,
        limit: int,
    ) -> PurgeResultV1: ...
```

Все unscoped result-read/mutation signatures удалить; canonical control API всегда
принимает authenticated principal и mission binding. Legacy `get_results()` может
временно существовать только как mission-scoped compatibility wrapper поверх
`list_results()` и никогда не удаляет/acknowledges rows.

Semantics:

```text
LIST_AGENTS: read-only, mission-scoped
LIST_RESULTS: read-only, no row mutation/deletion
ACK_RESULTS: explicit operator mutation over result refs/revisions; retains result row
PURGE_RESULTS: ADMIN-only bounded retention mutation
AgentTaskDeliveryAckV12: agent delivery receipt only; never operator result acknowledgement
```

READONLY разрешено читать только resources missions, на которые principal имеет
explicit grant.

C2 DB migration adds canonical binding:

```text
agents:
    mission_id
    owner_subject_id
    authorization_revision
    deployment_ref
    protocol_version

tasks/results:
    mission_id
    owner_subject_id
    agent_id
    authorization_revision
```

Add normalized tables:

```text
operator_peer_bindings(
    binding_id, operator_id, peer_uid, peer_gid, state, revision,
    created_at, revoked_at, revoked_by_subject_id
)
operator_mission_grants(
    grant_id, operator_id, subject_id, mission_id, role, scope_revision, state,
    created_at, revoked_at, revoked_by_subject_id
)
resource_acl_entries
task_delivery_receipts
result_acknowledgements
```

`task_delivery_receipts` stores agent delivery state independently from
`result_acknowledgements`, which stores operator subject, result revision and ack
revision. Existing rows do not receive global access automatically. They become
`LEGACY_UNASSIGNED` and remain invisible until explicit ADMIN binding.

Denied and missing foreign resources return the same external result.

Tests:

```text
test_readonly_cannot_list_agents_from_other_mission
test_readonly_cannot_list_results_from_other_mission
test_agent_id_does_not_bypass_mission_acl
test_list_results_requires_resource_acl
test_c2_control_page_and_result_dtos_exact_fields
test_no_bare_agent_page_result_page_purge_result_aliases
test_list_results_does_not_delete_or_mutate
test_result_ack_model_is_distinct_from_task_delivery_ack
test_ack_results_rejects_delivery_ack_payload
test_ack_results_requires_result_ref_revision
test_ack_results_is_explicit_mutation
test_purge_results_bounded_admin_only
test_legacy_get_results_wrapper_requires_mission_acl
test_legacy_unassigned_rows_are_not_visible
test_existing_operator_requires_explicit_peer_and_mission_binding
```

## 14.8. Single outbound IPC path и routing ownership

Delete `_send_to_daemon`, `_cached_api_key` socket implementation and direct
client-side `AF_UNIX` connects from CLI/first-party code. Only
`core/c2/client.py` may connect outbound. CLI never invokes `C2ControlClient`
directly.

Operational C2 mutations always enter the canonical action lifecycle:

```text
c2_task action
c2_enroll action
dns_c2_channel action
c2_deploy action
c2_cleanup action

CLI/application intent
→ closed typed ActionRequestV2
→ ActionExecutor
→ concrete provider
→ C2ControlClient when required
```

Administrative/read-control operations use an authenticated application service,
not `ActionExecutor`:

```text
LIST_AGENTS
LIST_RESULTS
ACK_RESULTS
PURGE_RESULTS
MANAGE_OPERATORS_*
SYNC_OPERATOR_PEER_BINDINGS
REVOKE_OPERATOR_PEER_BINDING
SYNC_OPERATOR_MISSION_GRANTS
REVOKE_OPERATOR_MISSION_GRANT

CLI/admin API
→ C2ApplicationService
→ ingress/peer/operator/mission/RBAC authorization
→ C2ControlClient
```

`C2ApplicationService` is the only first-party caller for administrative
`ACK/PURGE/MANAGE/SYNC/REVOKE` operations. It is not a bypass for operational
actions and cannot queue tasks, issue enrollment, create channels, deploy or
cleanup resources.

Tests:

```text
test_operational_c2_mutations_require_action_executor
test_admin_ack_purge_manage_sync_use_application_service
test_cli_never_calls_c2_control_client_directly
test_application_service_cannot_queue_task_or_create_channel
test_action_executor_does_not_own_admin_ack_purge_manage_sync
```

## 14.9. Audit/redaction

Audit stores only identities, peer IDs, request/action/schema digests, result code, duration and replay flag.

Forbidden:

```text
API keys
raw commands
raw task output
full payload/response
password/hash/ticket/token
artifact local path
secret-bearing exception repr
```

## Acceptance

```text
single outbound IPC path
static production UID/GID and compatible socket ACL
server validates clients with SO_PEERCRED on accepted sockets
client authenticates daemon with pinned signed handshake under socket activation
API key is never sent before daemon identity verification
operator/peer/subject/mission/RBAC binding enforced
idempotency is mission+subject+action bound
LIST_RESULTS non-destructive
ACK_RESULTS explicit mutation through C2ApplicationService
PURGE_RESULTS admin-only retention mutation through C2ApplicationService
root-owned first-admin bootstrap exists and automatic default-admin creation is removed
peer/mission grant sync/revocation is revisioned and ADMIN-only
operational C2 mutations cannot bypass ActionExecutor
```

## Required tests

```text
test_service_unit_has_no_dynamic_user
test_service_unit_static_user_group
test_sysusers_tmpfiles_packaged
test_socket_owner_group_mode_contract
test_reference_readiness_rejects_dynamic_or_unknown_uid

test_uint32_big_endian_frame
test_zero_oversized_partial_trailing_frames_rejected
test_control_connection_requires_exact_four_frames
test_control_exchange_is_four_frames_not_two_frame_request_response
test_control_frames_reject_out_of_order_messages
test_authenticated_request_rejected_before_server_challenge_verification
test_fd_activation_harness_proves_client_peercred_is_activator_not_daemon
test_client_validates_signed_server_identity_before_auth
test_client_rejects_wrong_pinned_server_key
test_client_rejects_listener_inode_mismatch
test_api_key_not_sent_before_server_identity_verified
test_server_validates_client_so_peercred
test_systemd_socket_activation_e2e_signed_server_identity
test_operator_peer_subject_mission_binding
test_request_role_cannot_escalate
test_full_rbac_matrix
test_readonly_list_results_allowed
test_readonly_ack_results_denied
test_operator_purge_results_denied

test_c2_control_page_and_result_dtos_exact_fields
test_no_bare_agent_page_result_page_purge_result_aliases
test_list_results_does_not_delete_or_mutate
test_ack_results_marks_and_retains
test_purge_results_bounded_admin_only
test_legacy_get_results_is_non_destructive

test_idempotency_subject_mission_action_binding
test_db_side_effect_atomic_with_idempotency
test_external_side_effect_has_durable_pending_before_effect
test_pending_control_command_reconciled
test_daemon_resource_prepare_commit_abort_reconcile_roundtrip
test_daemon_resource_stays_pending_until_local_commit_decision

test_cli_has_no_send_to_daemon
test_ast_single_outbound_unix_socket_path
test_cli_queue_task_cannot_call_client_directly
test_api_key_and_canary_absent_from_logs_audit_responses
```

## Definition of done

```text
provider count remains 14/20
control IPC ready
production identity stable
result semantics migrated
no second outbound IPC path
```

---

# PR-15. Agent protocol V12 и enrollment-aware builder/implant migration

## Цель

Мигрировать current Go/Python agents, daemon task storage и все production builder call sites с raw `command`/implicit token issuance на typed agent wire и explicit enrollment checkout до mount `c2_task`/`c2_deploy`.

Provider count остаётся `14/20`.

## CREATE

```text
core/c2/agent_protocol_v12.py
core/c2/agent_task_catalog.py
core/c2/agent_task_codec.py
core/c2/agent_capabilities.py
core/c2/agent_result_models.py
core/c2/artifact_builder.py
core/c2/artifact_rebinder.py
core/c2/enrollment_models.py
core/c2/enrollment_build_checkout.py
core/c2/enrollment_control_models.py
core/c2/enrollment_control_codec.py
core/c2/artifact_bindings.py
scripts/quality/c2_raw_task_inventory.py
scripts/quality/c2_builder_enrollment_inventory.py
tests/test_c2_agent_protocol_v12.py
tests/test_c2_agent_task_catalog.py
tests/test_c2_agent_capability_negotiation.py
tests/test_c2_agent_task_result_decoder.py
tests/test_c2_task_schema_migration.py
tests/test_c2_builder_enrollment_migration.py
tests/test_c2_enrollment_models.py
tests/test_c2_enrollment_control_codec.py
tests/test_c2_artifact_rebinder.py
tests/test_c2_artifact_bindings.py
tests/test_c2_raw_task_inventory.py
```

## MODIFY

```text
core/c2/protocol.py
core/c2/agent_task_models.py
core/c2/daemon.py
core/c2/db_backend.py
core/c2/enrollment.py
core/c2/client.py
core/c2/control_models.py
core/c2/resource_payload_registry.py
core/actions/reference_snapshots.py
core/actions/checkout_models.py
core/actions/materials.py
core/runtime_config.py
config.py
config.yaml
.env.example
core/c2/builder.py
core/c2/implant.go
core/c2/implant_test.go
core/c2/implants/python_implant.py
core/tools/runner.py
core/tools/post_tools.py
core/cli/application.py
core/cli/menu_bridge.py
core/ai/tool_registry.py
README.md
docs/architecture/contracts-and-ownership.md
docs/architecture/current-system-map.md
tests/test_c2_daemon_coverage.py
tests/test_c2_builder_and_stager_coverage.py
tests/test_tools_runner_coverage.py
tests/test_cli_application_menus_coverage.py
```

## 15.1. Agent protocol negotiation

PR-15 imports only `C2_AGENT_PROTOCOL_V11`, `C2_AGENT_PROTOCOL_V12` and
`C2_TASK_SCHEMA_V12` from the PR-6 owner; it declares no protocol aliases.

Registration V12 advertises:

```text
protocol version
supported operation IDs
supported payload schema versions
supported result schema versions
deployment ref
artifact binding digest
```

`AgentWireCodecV12` is the sole bounded wire codec for all V12 agent messages,
including the host-side `AgentRegistrationV12` model, and follows the
zeroizable lease contract in §10.6; generic JSON/dataclass serialization is
forbidden.

`artifact_binding_digest` uses only the full canonical non-self-referential
formula in §10.8. PR-15 must import the same serializer/digest helper from
`core/c2/artifact_bindings.py`; it must not define a shortened field set or a
second formula. The digest contains no plaintext enrollment token or local path.

Daemon persists protocol, operation/payload/result capability sets, artifact_binding_digest and capability revision on the agent row and uses them as request preconditions.

`c2_task` is executable only when the selected agent advertises the exact
`C2TaskOperationId`, `AgentPayloadSchemaIdV12` and `AgentResultSchemaIdV12`
triple chosen by the compiler. Missing result-schema capability is a request
precondition failure, not provider readiness.

## 15.2. Canonical closed V12 task/result/delivery DTOs

These are the only normative V12 agent-wire task/result definitions in the plan.
They are separate from the control-plane payload DTOs in PR-6.

Wire payload DTOs:

```python
@dataclass(frozen=True)
class AgentIdentityTaskPayloadV12:
    payload_kind: Literal["identity"] = field(default="identity", init=False)
    schema_version: Literal["c2-agent-payload/identity/1"] = field(default="c2-agent-payload/identity/1", init=False)


@dataclass(frozen=True)
class AgentHostInventoryTaskPayloadV12:
    include_processes: bool
    include_services: bool
    max_items: int
    payload_kind: Literal["host_inventory"] = field(default="host_inventory", init=False)
    schema_version: Literal["c2-agent-payload/host-inventory/1"] = field(
        default="c2-agent-payload/host-inventory/1", init=False
    )


@dataclass(frozen=True)
class AgentNetworkInventoryTaskPayloadV12:
    include_routes: bool
    include_connections: bool
    max_items: int
    payload_kind: Literal["network_inventory"] = field(default="network_inventory", init=False)
    schema_version: Literal["c2-agent-payload/network-inventory/1"] = field(
        default="c2-agent-payload/network-inventory/1", init=False
    )


@dataclass(frozen=True)
class AgentServiceInventoryTaskPayloadV12:
    service_names: tuple[str, ...]
    include_status: bool
    payload_kind: Literal["service_inventory"] = field(default="service_inventory", init=False)
    schema_version: Literal["c2-agent-payload/service-inventory/1"] = field(
        default="c2-agent-payload/service-inventory/1", init=False
    )


AgentTaskPayloadV12 = (
    AgentIdentityTaskPayloadV12
    | AgentHostInventoryTaskPayloadV12
    | AgentNetworkInventoryTaskPayloadV12
    | AgentServiceInventoryTaskPayloadV12
)
```

Task/result schema IDs and ownership:

`C2TaskOperationId` импортируется только из `core/c2/task_catalog.py` (PR-6).
`AgentPayloadSchemaIdV12` и `AgentResultSchemaIdV12` импортируются только из
`core/c2/agent_task_protocol.py` (PR-6). PR-15 не переопределяет эти enums.

Canonical mapping:

```text
IDENTITY          → payload IDENTITY_V1          → result IDENTITY_V1
HOST_INVENTORY    → payload HOST_INVENTORY_V1    → result HOST_INVENTORY_V1
NETWORK_INVENTORY → payload NETWORK_INVENTORY_V1 → result NETWORK_INVENTORY_V1
SERVICE_INVENTORY → payload SERVICE_INVENTORY_V1 → result SERVICE_INVENTORY_V1
```

Task envelope:

```python
@dataclass(frozen=True)
class AgentTaskEnvelopeV12:
    schema_version: Literal["12.0"]
    task_id: str
    operation_id: C2TaskOperationId
    payload_schema_version: AgentPayloadSchemaIdV12
    result_schema_version: AgentResultSchemaIdV12
    expected_agent_capabilities_revision: int
    expected_agent_capabilities_digest: str
    expected_agent_artifact_binding_digest: str
    payload: AgentTaskPayloadV12
    issued_at: float
    expires_at: float
    delivery_attempt: int
```

Closed result support types:

```python
class AgentTaskStatus(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    PARTIAL = "partial"
    CANCELLED = "cancelled"
    TIMED_OUT = "timed_out"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    INVALID_PAYLOAD = "invalid_payload"


class AgentTaskErrorCode(str, Enum):
    INVALID_PAYLOAD = "invalid_payload"
    UNSUPPORTED_OPERATION = "unsupported_operation"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    OUTPUT_LIMIT = "output_limit"
    EXECUTION_FAILED = "execution_failed"


@dataclass(frozen=True)
class AgentProcessSummaryV12:
    pid: int
    name: str


@dataclass(frozen=True)
class AgentServiceSummaryV12:
    name: str
    status: str


@dataclass(frozen=True)
class AgentInterfaceSummaryV12:
    name: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class AgentRouteSummaryV12:
    destination: str
    gateway: str | None
    interface: str


@dataclass(frozen=True)
class AgentConnectionSummaryV12:
    protocol: NetworkProtocol
    local_endpoint: str
    remote_endpoint: str | None
    state: str


@dataclass(frozen=True)
class AgentIdentityTaskOutputV12:
    schema_version: Literal["c2-agent-result/identity/1"] = field(default="c2-agent-result/identity/1", init=False)
    output_kind: Literal["identity"] = field(default="identity", init=False)
    hostname: str
    os: C2TargetOS
    arch: C2TargetArch
    user: str
    process_id: int


@dataclass(frozen=True)
class AgentHostInventoryTaskOutputV12:
    schema_version: Literal["c2-agent-result/host-inventory/1"] = field(
        default="c2-agent-result/host-inventory/1", init=False
    )
    output_kind: Literal["host_inventory"] = field(default="host_inventory", init=False)
    processes: tuple[AgentProcessSummaryV12, ...]
    services: tuple[AgentServiceSummaryV12, ...]
    truncated: bool


@dataclass(frozen=True)
class AgentNetworkInventoryTaskOutputV12:
    schema_version: Literal["c2-agent-result/network-inventory/1"] = field(
        default="c2-agent-result/network-inventory/1", init=False
    )
    output_kind: Literal["network_inventory"] = field(default="network_inventory", init=False)
    interfaces: tuple[AgentInterfaceSummaryV12, ...]
    routes: tuple[AgentRouteSummaryV12, ...]
    connections: tuple[AgentConnectionSummaryV12, ...]
    truncated: bool


@dataclass(frozen=True)
class AgentServiceInventoryTaskOutputV12:
    schema_version: Literal["c2-agent-result/service-inventory/1"] = field(
        default="c2-agent-result/service-inventory/1", init=False
    )
    output_kind: Literal["service_inventory"] = field(default="service_inventory", init=False)
    services: tuple[AgentServiceSummaryV12, ...]
    truncated: bool


AgentTaskOutput = (
    AgentIdentityTaskOutputV12
    | AgentHostInventoryTaskOutputV12
    | AgentNetworkInventoryTaskOutputV12
    | AgentServiceInventoryTaskOutputV12
)
```

Result envelope:

```python
@dataclass(frozen=True)
class AgentTaskResultV12:
    schema_version: Literal["12.0"]
    result_schema_version: AgentResultSchemaIdV12
    result_id: str
    task_id: str
    operation_id: C2TaskOperationId
    status: AgentTaskStatus
    output: AgentTaskOutput | None
    error_code: AgentTaskErrorCode | None
    completed_at: float
```

Ownership:

```text
C2TaskOperationId       → core/c2/task_catalog.py (PR-6)
AgentPayloadSchemaIdV12 → core/c2/agent_task_protocol.py (PR-6)
AgentResultSchemaIdV12  → core/c2/agent_task_protocol.py (PR-6)
AgentTaskStatus         → core/c2/agent_task_models.py (PR-15)
AgentTaskErrorCode      → core/c2/agent_task_models.py (PR-15)
```

Validation invariants:

```text
envelope.payload_schema_version == envelope.payload.schema_version
envelope operation/payload/result triple equals canonical mapping
result.result_schema_version == envelope.result_schema_version
if result.output is not None:
    result.output.schema_version == result.result_schema_version
    output variant matches operation_id
SUCCEEDED requires output and error_code=None
PARTIAL requires output; error_code may describe truncation/partial failure
FAILED/CANCELLED/TIMED_OUT/UNSUPPORTED_OPERATION/INVALID_PAYLOAD require error_code
error result may have output=None but retains requested result_schema_version
agent registration must advertise operation, payload schema and result schema
```

Result acceptance uses one bounded exact decoder owned by
`core/c2/agent_task_codec.py`:

```python
class AgentTaskResultDecoderV12:
    def decode(
        self,
        serialized_result: bytes,
        *,
        expected_envelope: AgentTaskEnvelopeV12,
        authenticated_agent_ref: str,
    ) -> AgentTaskResultV12: ...
```

The decoder resolves its immutable `AgentTaskResultDecodePolicyV12` from the daemon-owned `AgentTaskResultDecodePolicyRegistryV12`. No call site may pass limit values, a narrowing DTO or a replacement policy. Decoder rejects unknown fields,
duplicate JSON keys, oversized/deep payloads and non-canonical variants. Before
staging a result row it proves:

```text
result.task_id == expected_envelope.task_id
result.operation_id == expected_envelope.operation_id
result.result_schema_version == expected_envelope.result_schema_version
result output variant/schema matches the expected operation/result mapping
authenticated agent owns the persisted expected task
delivery/task state permits exactly one idempotent result transition
```

A mismatched task ID, operation ID or result schema is
`agent_result_envelope_mismatch` and does not update task/result state.

Отдельного output-schema поля не существует. `result_schema_version` is the only
schema selector for the closed output/result variant.

Agent delivery acknowledgement:

```python
@dataclass(frozen=True)
class AgentTaskDeliveryAckV12:
    schema_version: Literal["12.0"]
    task_id: str
    delivery_attempt: int
    received_at: float
```

One exact wire codec and frame owner exists in
`core/c2/agent_task_codec.py`:

```python
class AgentWireMessageKindV12(IntEnum):
    REGISTRATION = 1
    TASK = 2
    RESULT = 3
    DELIVERY_ACK = 4


@dataclass(frozen=True)
class AgentWireFrameHeaderV12:
    magic: Literal["OCT12"]
    wire_version: Literal[1]
    message_kind: AgentWireMessageKindV12
    canonical_body_length: int
    secret_segment_length: int
    canonical_body_digest: str
    secret_integrity_tag_length: int
    secret_segment_integrity_tag: SensitiveIntegrityTagV2 | None


@runtime_checkable
class AgentWireCodecV12(Protocol):
    def encode_registration_into_zeroizable(
        self,
        registration: AgentRegistrationV12,
        destination: ZeroizableDestinationBufferV2,
    ) -> int: ...

    def decode_registration_from_zeroizable(
        self,
        frame_reader: BoundedFrameReaderV1,
    ) -> AgentRegistrationV12: ...

    def encode_task(self, task: AgentTaskEnvelopeV12) -> bytes: ...
    def decode_task(self, frame: bytes) -> AgentTaskEnvelopeV12: ...
    def encode_result(self, result: AgentTaskResultV12) -> bytes: ...
    def decode_result(
        self,
        frame: bytes,
        *,
        expected_envelope: AgentTaskEnvelopeV12,
        authenticated_agent_ref: str,
    ) -> AgentTaskResultV12: ...
    def encode_delivery_ack(self, ack: AgentTaskDeliveryAckV12) -> bytes: ...
    def decode_delivery_ack(self, frame: bytes) -> AgentTaskDeliveryAckV12: ...
```

Frame bytes are exactly:

```text
4-byte ASCII magic "OCT12"
1-byte wire version = 1
1-byte AgentWireMessageKindV12
4-byte unsigned big-endian canonical-body length
4-byte unsigned big-endian secret-segment length
32-byte SHA-256 canonical-body digest
2-byte unsigned big-endian canonical secret-integrity-tag metadata length
canonical RFC-8785 `SensitiveIntegrityTagV2` metadata bytes (zero length iff
secret length is zero; opaque key ID/algorithm/domain/tag, never key material)
canonical RFC-8785 JSON body bytes
optional raw secret segment
```

Only REGISTRATION permits a nonzero secret segment. Its canonical body contains
token length/keyed integrity tag but never token bytes or an unkeyed plaintext
digest; the encoder copies the token lease
directly into the final zeroizable frame, and the decoder transfers that segment
directly into `OpaqueSecretValueV2` and constant-time verifies the exact
domain/keyed tag through the server authenticator. TASK/RESULT/DELIVERY_ACK require secret
length zero and may return immutable frame bytes. Decoder rejects unknown
message kind/field, duplicate JSON keys, non-canonical body, digest/length
mismatch, trailing bytes, invalid UTF-8, nesting over 8, strings over 65,536
bytes and frames over 1,048,576 bytes. Per-message collection limits are the
validated registry limits below. Python and Go share byte-for-byte golden
vectors for all four kinds, malformed inputs and registration zeroization.

`AgentTaskResultDecoderV12` is a narrow application validator that delegates
wire decoding to this sole codec and then enforces persisted task/agent state;
it does not define another serialization format.

`C2TaskCompiler` selects one canonical operation/payload/result triple.
All three values must be advertised by `AgentCapabilitySetV12`. Daemon
preconditions and agent startup registry reject any unsupported operation,
payload schema or result schema. Agent validates payload and returned output
schema IDs against the envelope/result exactly.

Operator result acknowledgement is not part of the agent wire and uses only the
`ResultAckRequestV1` model defined in PR-14 §14.7.

Go/Python agents use exhaustive closed handler and output registries. V12 code
contains no wire-provided arbitrary command/argv execution path, open payload
map or open result metadata map.

## 15.2A. Canonical V12 result decoder limits

Owner: `core/c2/agent_task_codec.py`; configuration owner:
`core/runtime_config.py`.

```python
@dataclass(frozen=True)
class AgentTaskResultDecodeLimitsV12:
    max_frame_bytes: int = 1_048_576
    max_depth: int = 8
    max_string_bytes: int = 65_536
    max_collection_items: int = 1_024
    max_processes: int = 1_024
    max_services: int = 1_024
    max_interfaces: int = 256
    max_routes: int = 1_024
    max_connections: int = 2_048


@dataclass(frozen=True)
class AgentTaskResultDecodePolicyV12:
    policy_id: str
    policy_revision: int
    limits: AgentTaskResultDecodeLimitsV12
    config_digest: str


@runtime_checkable
class AgentTaskResultDecodePolicyRegistryV12(Protocol):
    def current(self) -> AgentTaskResultDecodePolicyV12: ...
```

Hard maxima:

```text
max_frame_bytes       <= 4_194_304
max_depth             <= 16
max_string_bytes      <= 262_144
max_collection_items  <= 4_096
max_processes         <= 4_096
max_services          <= 4_096
max_interfaces        <= 1_024
max_routes            <= 4_096
max_connections       <= 8_192
```

Config keys:

```yaml
c2:
  agent_v12:
    result_decoder:
      max_frame_bytes: 1048576
      max_depth: 8
      max_string_bytes: 65536
      max_collection_items: 1024
      max_processes: 1024
      max_services: 1024
      max_interfaces: 256
      max_routes: 1024
      max_connections: 2048
```

Exact environment overrides:

```text
OCTOPUS_C2_AGENT_V12_RESULT_DECODER_MAX_FRAME_BYTES
OCTOPUS_C2_AGENT_V12_RESULT_DECODER_MAX_DEPTH
OCTOPUS_C2_AGENT_V12_RESULT_DECODER_MAX_STRING_BYTES
OCTOPUS_C2_AGENT_V12_RESULT_DECODER_MAX_COLLECTION_ITEMS
OCTOPUS_C2_AGENT_V12_RESULT_DECODER_MAX_PROCESSES
OCTOPUS_C2_AGENT_V12_RESULT_DECODER_MAX_SERVICES
OCTOPUS_C2_AGENT_V12_RESULT_DECODER_MAX_INTERFACES
OCTOPUS_C2_AGENT_V12_RESULT_DECODER_MAX_ROUTES
OCTOPUS_C2_AGENT_V12_RESULT_DECODER_MAX_CONNECTIONS
```

Startup rejects non-integers, values below 1, contradictory collection limits and values above hard maxima. `AgentTaskResultDecodePolicyRegistryV12` creates one immutable policy from validated config. Call sites provide only the authenticated agent and expected envelope; they cannot supply, narrow or widen limits.

`AgentTaskResultDecoderV12.decode(...)` loads the canonical configured policy from its owned registry on every decode generation and accepts no call-site limit argument. It validates exact
schema, bounded JSON shape, `task_id`, `operation_id`, requested result schema,
output variant and status/error invariants before creating any DTO.

Required tests:

```text
test_v12_result_decoder_uses_canonical_defaults
test_v12_result_decoder_rejects_limit_above_hard_max
test_v12_result_decoder_has_no_call_site_limit_parameter
test_v12_result_decoder_loads_policy_only_from_registry
test_v12_result_decoder_config_validation_fail_closed
test_v12_result_decoder_exact_environment_override_keys
test_v12_result_decoder_bounds_each_collection_variant
test_v12_result_decoder_task_and_operation_match_expected_envelope
```

## 15.3. DB capability, task, result and ACK migration

Persist exact V12 registration capabilities on `agents`:

```text
protocol_version
supported_operation_ids_json
supported_payload_schema_versions_json
supported_result_schema_versions_json
artifact_binding_digest
capabilities_digest
capabilities_revision
```

Persist canonical tasks:

```text
task_schema_version
operation_id
payload_schema_version
result_schema_version
payload_json
payload_digest
agent_protocol_version
expected_agent_capabilities_revision
expected_agent_capabilities_digest
expected_agent_artifact_binding_digest
delivery_attempt
```

The compiler copies the selected authenticated agent row's capability revision,
capability digest and artifact-binding digest into both envelope and task row.
The daemon revalidates exact equality before hidden finalize, before a task
becomes leaseable, on every delivery lease and when accepting a result. Any
agent capability revocation/re-registration or artifact rebind makes the task
non-leaseable and yields a typed stale-capability disposition; it is never
silently delivered under the new capability set. Result validation binds back
to the persisted expected triple as well as task/operation/schema IDs.

Persist canonical results:

```text
result_id
result_schema_version
operation_id
result_json
result_digest
result_revision
```

Persist delivery and operator ACKs in separate tables:

```text
task_delivery_receipts(task_id, delivery_attempt, agent_id, received_at, receipt_digest)
result_acknowledgements(result_id, mission_id, subject_id, result_revision, acknowledged_at, acknowledgement_revision)
```

Legacy `command` remains nullable only for V11 migration rows and is not canonical.
Legacy result rows are migrated to schema-versioned result records or remain
`LEGACY_UNASSIGNED`.

Migration policy:

```text
pending V11 raw tasks are explicitly cancelled/quarantined or completed under legacy-only mode
no automatic translation from arbitrary command to typed operation
new V11 raw task emission disabled by default
V11 agents observable but not eligible for typed c2_task
result acknowledgement never reuses task delivery acknowledgement
```

Required tests:

```text
test_v12_agent_capabilities_persist_operation_payload_result_sets
test_v12_capability_digest_recomputed_by_daemon
test_v12_agent_artifact_binding_digest_persisted
test_capability_revision_changes_on_reregistration
test_v12_task_db_roundtrip
test_v12_result_db_roundtrip
test_v12_result_decoder_exact_schema_and_bounds
test_v12_result_decoder_rejects_unknown_fields_and_duplicate_keys
test_v12_result_task_id_matches_envelope
test_v12_result_operation_id_matches_envelope
test_v12_result_authenticated_agent_owns_task
test_v12_result_decoder_rejects_caller_dataclass
test_result_schema_equals_requested_envelope_schema
test_result_output_variant_matches_result_schema
test_result_schema_operation_mapping_is_exact
test_error_result_retains_requested_result_schema
test_c2_task_requires_result_schema_capability
test_c2_task_operation_status_error_owners_are_unique
test_delivery_receipt_and_result_ack_tables_are_separate
test_operator_result_ack_cannot_mutate_task_delivery_state
```

## 15.4. Go agent migration

Modify `implant.go`:

```text
replace []map[string]string tasks with typed structs
remove task["command"]
remove strings.Fields(command)
remove exec.CommandContext driven by wire-provided argv
add exhaustive operation handler switch/registry
add typed result encoding
```

Compile/test Go agent protocol vectors.

## 15.5. Python generated agent migration

Modify generated source template:

```text
remove _execute_command fallback for V12 task wire
remove command-prefix download/upload/selfdestruct router
replace with closed operation handlers and typed payload decoders
return typed result envelope
```

Any developer-only raw-command agent must use a separate protocol/profile and cannot register as V12 or be selected by typed `c2_task`.

## 15.6. Enrollment-aware builder migration

Current production signatures that accept optional plaintext `enrollment_token` or auto-call `EnrollmentAuthority.issue()` are removed.

PR-15 imports the sole `C2ArtifactBuilder` and `C2ArtifactRebinder` Protocols
defined in §10.8; it must not redeclare either symbol. Their exact `build(...)`
and `rebind(...)` signatures are the authoritative APIs for this migration.

The provider then performs exactly one staging call:

```python
staged_artifact = invocation.staging.stage_c2_artifact(stage_request)
```

Builder/rebinder never return `StagedC2Artifact` and never receive staging,
participant-registration or commit-coordinator capabilities.

The private `EnrollmentBuildCheckout` is executor/daemon-issued, transaction
bound, excluded from provider context/repr/audit and closed in outer `finally`.
Builders receive only its `EnrollmentBuildMaterialViewV1`.

Migration inventory covers:

```text
core/c2/builder.py
core/c2/implants/python_implant.py
Go build path
Python build path
PowerShell stager/build path discovered by inventory
core/tools/runner.py
core/tools/post_tools.py
CLI C2 build menu/menu bridge
tests and docs examples
```

Production builder call sites receive one `C2ArtifactBuildRequest`, one
executor-issued `EnrollmentBuildMaterialViewV1`, and one restricted
`C2ArtifactBuildContext`; the request contains a `C2ArtifactBuildBinding` with
the preallocated `deployment_ref` and:

```text
enrollment checkout/ref/revision
channel ref
target/profile/method/protocol binding
mission/subject binding
source binding digest
current C2ArtifactBuildContext
    - context.scope
    - context.budget
    - context.lineage

The builder/rebinder receives no `BoundProviderInvocationContext`, staging
facade, participant facade, transaction ID or coordinator capability.
```

Builder or reviewed rebinder computes the final artifact content digest first,
then calls the single canonical full `artifact_binding_digest` helper from
§10.8. Neither implementation receives or derives `deployment_ref` implicitly;
the rebinder creates a new artifact blob and never mutates the prebuilt source.

Artifact metadata stores only opaque refs/digests, not token.

## 15.7. Enrollment state migration

State machine:

```text
ISSUED
→ RESERVED_FOR_BUILD
→ EMBEDDED_IN_ARTIFACT
→ RESERVED_FOR_DEPLOYMENT
→ CONSUMED_BY_AGENT
```

Terminal:

```text
REVOKED
EXPIRED
```

Existing consumed-token table is migrated or bridged with schema-versioned records. Registration atomically consumes the exact enrollment bound to artifact/deployment/agent.

## Architecture gates

```text
no V12 command field
no Go/Python V12 arbitrary process execution from wire
no production builder default enrollment token
no direct EnrollmentAuthority.issue() in builder/generator call sites
all builder paths present in inventory allowlist
```

## Acceptance

```text
Go/Python agents negotiate V12 and closed operations
c2_task can target only V12-capable agents
DB canonical task schema is operation/payload based
legacy raw tasks cannot enter typed provider path
all production builders require enrollment checkout
no builder/generator self-issues enrollment
artifact metadata binds deployment/enrollment/channel/target/profile/method/protocol/source and the full artifact_binding_digest
prebuilt source is accepted only through reviewed C2ArtifactRebinder
```

## Required tests

```text
test_v12_registration_capability_roundtrip
test_v12_task_and_result_vectors_python
test_v12_task_and_result_vectors_go
test_go_agent_has_no_v12_raw_command_path
test_generated_python_agent_has_no_v12_raw_command_path
test_unknown_operation_or_payload_schema_rejected
test_v11_agent_not_eligible_for_typed_task
test_no_new_v11_raw_tasks_after_cutover
test_pending_v11_task_migration_policy

test_builder_requires_enrollment_checkout
test_builder_has_no_auto_issue_path
test_python_generator_has_no_auto_issue_path
test_all_builder_call_sites_inventory_complete
test_build_checkout_binding_mismatch_denied
test_builder_requires_preallocated_deployment_ref_binding
test_builder_receives_c2_artifact_build_request
test_builder_returns_unstaged_c2_artifact_build_output
test_provider_stages_c2_artifact_exactly_once
test_builder_has_no_staging_or_commit_capability
test_artifact_metadata_contains_opaque_bindings_only
test_artifact_binding_digest_is_non_self_referential
test_artifact_binding_digest_uses_single_full_field_set
test_artifact_binding_digest_matches_registration_and_db
test_prebuilt_artifact_requires_rebind_manifest
test_prebuilt_rebinder_creates_new_blob_and_deployment_binding
test_generic_prebuilt_artifact_is_rejected
test_build_failure_releases_or_revokes_reservation
test_registration_consumes_bound_enrollment_atomically
test_enrollment_build_checkout_state_machine_exact
test_close_before_material_exposure_releases_reservation
test_close_after_material_exposure_revokes_enrollment
test_transfer_moves_reservation_ownership_to_participant
test_orphan_build_reservation_reconciles_on_startup
test_enrollment_issue_max_uses_is_exactly_one
test_agent_registration_codec_never_generic_serializes_secret_value
test_agent_registration_codec_python_go_vectors_and_zeroization
```

## Definition of done

```text
provider count remains 14/20
agent V12 wire complete
builder/implant enrollment migration complete
c2_task and c2_deploy may now be mounted
```

---

# PR-16. Подключение `c2_enroll`, `c2_task`, `c2_cleanup`, `c2_deploy`

## Цель

Подключить четыре C2 provider identities после control IPC и agent/builder migrations, сохранив одного lifecycle owner для каждого resource kind.

## CREATE

```text
core/c2/deployment.py
core/c2/deployment_backends.py
core/c2/deployment_store.py
core/c2/deployment_cleanup.py
core/c2/deployment_outbox.py
core/c2/enrollment_service.py
core/c2/deployment_effect_participant.py
core/c2/deployment_effect_models.py
core/c2/cleanup_effect_models.py
core/c2/cleanup_effect_participant.py
core/c2/enrollment_transaction_participant.py
core/c2/task_compiler.py
core/c2/resource_models.py
core/c2/deployment_attempts.py
core/providers/c2_enroll.py
core/providers/c2_task.py
core/providers/c2_cleanup.py
core/providers/c2_deploy.py
tests/test_c2_enroll_provider.py
tests/test_c2_task_provider.py
tests/test_c2_task_compiler.py
tests/test_c2_cleanup_provider.py
tests/test_c2_deploy_provider.py
tests/test_c2_deployment_ownership.py
tests/test_c2_enrollment_transaction_participant.py
tests/test_c2_deployment_exactly_once.py
tests/integration/test_c2_lifecycle_providers_e2e.py
```

## MODIFY

```text
core/actions/adapters_c2.py
core/actions/input_contracts.py
core/actions/provider_mounts.py
core/actions/readiness_probes.py
core/actions/provider_results.py
core/actions/executor.py
core/c2/client.py
core/c2/control_models.py
core/c2/control_commands.py
core/c2/control_transactions.py
core/c2/control_rbac.py
core/c2/resource_participant.py
core/c2/resource_participant_models.py
core/c2/daemon.py
core/c2/enrollment.py
core/c2/enrollment_models.py
core/c2/db_backend.py
core/c2/event_store.py
core/c2/resources.py
core/sessions.py
core/artifacts.py
core/actions/operation_catalog.py
core/cli/application.py
tests/test_action_adapters_new.py
tests/test_high_risk_action_contracts.py
tests/test_c2_daemon_coverage.py
```

## 16.1. Common provider path

All four use:

```text
current authenticated ingress lease
executor-resolved principal/mission/approval
approval graph budget
trusted facts/target extraction
atomic reference checkout
initial + final readiness checks
one executor-built BoundProviderInvocationContext
    - materials
    - invocation scope/finally
    - restricted staging facade
    - restricted participant-registration facade
    - opaque transaction_id
    - budget/lineage
closed typed inputs/results
```

## 16.2. `c2_enroll`

Canonical execution classification:

```text
execution_node_kind=LEAF
provider_transport=LOCAL_DAEMON_IPC
```

The provider does not call a direct issue command. It:

```text
1. validates C2EnrollmentIssueInput and executor-owned ACL/scope;
2. canonical-encodes the exact enrollment prepare payload;
3. stages it as `StagedParticipantPayloadV2` (payload draft + internal
   participant registration);
4. registers CrossProcessResourceParticipantRegistrationPayloadV2 with
   `DeferredManagedResourceRequestV2(resource_kind=C2_ENROLLMENT, ...)` and
   explicit-finalize visibility; both dependency sets contain the staged
   payload registration and no transient ID exists;
5. receives CrossProcessResourceRegistrationResultV2;
6. returns C2ProviderResult(resources=(resource_draft_ref,)).
```

Coordinator lifecycle:

```text
PREPARE_C2_RESOURCE
    → daemon creates sealed bootstrap material and PENDING enrollment;

COMMIT_C2_RESOURCE
    → enrollment becomes COMMITTED_HIDDEN, not available to build checkout;

FINALIZE_C2_RESOURCE_VISIBILITY
    → enrollment becomes ISSUED and returns finalize ACK;

local coordinator COMMITTED
    → local c2-enrollment ref/result becomes normally readable.
```

Abort destroys sealed bootstrap material. Build material is obtainable only
after final enrollment visibility and through an executor-authorized
`EnrollmentBuildCheckout`.

## 16.3. `c2_task`

Canonical execution classification:

```text
execution_node_kind=LEAF
provider_transport=LOCAL_DAEMON_IPC
```

Request preconditions require an existing mission-bound V12 agent advertising
the exact operation, payload schema and result schema.

Flow:

```text
C2TaskInputV2
→ operation catalog
→ C2TaskCompiler.compile(...)
→ AgentTaskEnvelopeV12
→ canonical encode + stage participant payload
→ register CrossProcessResourceParticipantRegistrationPayloadV2(
    resource_request=DeferredManagedResourceRequestV2(resource_kind=C2_TASK, ...),
    prepare_depends_on=(staged_payload.registration_ref,),
    commit_depends_on=(staged_payload.registration_ref,))
→ PREPARE_C2_RESOURCE creates one hidden PENDING task row
→ COMMIT_C2_RESOURCE creates QUEUED_HIDDEN
→ FINALIZE_C2_RESOURCE_VISIBILITY creates QUEUED and finalize ACK
→ local coordinator COMMITTED publishes c2-task ref
```

No raw command is generated. The provider never calls `QUEUE_TYPED_TASK` and
the V12 beacon may lease only finalized `QUEUED` tasks. Idempotent replay of the
same local transaction does not create a second task.

Required tests:

```text
test_enroll_uses_cross_process_participant_only
test_enroll_hidden_commit_not_build_checkout_eligible
test_enroll_finalize_ack_precedes_local_ref_publication
test_task_uses_cross_process_participant_only
test_task_provider_never_calls_queue_typed_task
test_task_hidden_commit_not_beacon_leaseable
test_task_finalize_makes_exactly_one_row_leaseable
test_task_requires_operation_payload_and_result_capabilities
```

## 16.4. `c2_deploy` as staged plan + coordinator-owned participants

Canonical execution classification:

```text
execution_node_kind=LEAF
provider_transport=IN_PROCESS
canonical lifecycle owner=main-process DeploymentStore
```

`execute_bound()` performs no participant prepare and no remote upload/start. It
only builds/stages closed data and registers ordered participant specifications.

Provider phase:

```text
1. atomic checkout source/channel/enrollment/session and request idempotency;
2. take the executor-issued `EnrollmentBuildMaterialViewV1` from
   `BoundEnrollmentMaterial`; private checkout remains in the executor and the
   provider performs no daemon reserve/release call;
3. validate executor-issued `BoundDeploymentReservationV1` and take its
   preallocated deployment_ref;
4. construct C2ArtifactBuildBinding with that exact ref;
5. build or reviewed-rebind to C2ArtifactBuildOutput;
6. compute artifact_binding_digest before staging;
7. create `C2ArtifactStageRequestV1` and stage exactly once, receiving
   `C2ArtifactStageReceiptV1`, whose atomic return includes the internally
   registered artifact participant ref;
8. construct `StagedC2Artifact` from that receipt; no provider-visible local
   store registration occurs;
9. stage a closed `C2EnrollmentDeploymentPlanV1` payload and register the
   cross-process enrollment participant with
   `prepare_depends_on=(staged_artifact.artifact_participant_registration_ref,
   staged_plan.registration_ref)` and identical `commit_depends_on`;
   registration creates no daemon transition yet; after execute returns the
   executor validates the exact registration and privately calls
   `EnrollmentBuildCheckout.transfer_to_participant(registration_ref)` before
   verify;
10. allocate durable deployment_attempt_id;
11. stage a closed DeploymentStartPlanV1 payload;
12. register ExternalEffectParticipant(kind=DEPLOYMENT_START), with both
    dependency sets containing the enrollment participant and deployment-plan
    payload registration, and with a
    deferred deployment resource request bound to the exact preallocated ref;
    its registration result returns the matching local deployment resource draft;
13. return C2ProviderResult(resources=(deployment_draft,),
    artifacts=(artifact_stage,)).
14. outer finally always calls `EnrollmentBuildCheckout.close_checkout()`;
    transferred checkout is participant-owned, any earlier checkout is safely
    released or revoked according to exposure state.
```

Exact plan DTOs are owned by PR-16:

```python
@dataclass(frozen=True)
class C2EnrollmentDeploymentPlanV1:
    enrollment_ref: str
    enrollment_revision: int
    build_reservation_id: str
    artifact_draft_ref: SensitiveArtifactDraftRefV2
    artifact_sealed_record_digest: str
    artifact_integrity_tag: SensitiveIntegrityTagV2
    artifact_binding_digest: str
    deployment_ref: str
    deployment_request_digest: str
    mission_id: str
    subject_id: str


@dataclass(frozen=True)
class DeploymentStartPlanV1:
    deployment_attempt_id: str
    deployment_ref: str
    deployment_request_digest: str
    target: str
    access_session_ref: str
    artifact_draft_ref: SensitiveArtifactDraftRefV2
    artifact_sealed_record_digest: str
    artifact_integrity_tag: SensitiveIntegrityTagV2
    artifact_binding_digest: str
    channel_ref: str
    enrollment_ref: str
    profile_id: C2DeploymentProfileId
    method: C2DeploymentMethod
```

Coordinator prepare order is dependency-driven and is the only execution
continuation:

```text
ArtifactStore participant.prepare()  # identified by staged_artifact.artifact_participant_registration_ref
→ C2EnrollmentTransactionParticipant.prepare()  # exact prepare edge to artifact participant
    - atomically validate RESERVED_FOR_BUILD;
    - atomically perform MARK_ENROLLMENT_EMBEDDED semantics;
    - create EnrollmentEmbeddedReceipt;
    - atomically PREPARE enrollment deployment;
    - return EnrollmentPrepareReceipt;
→ every other rollbackable local resource/fact/result/audit participant.prepare()
→ DeploymentExternalEffectParticipant.prepare()  # terminal frontier, always last
    - durably journal START_DISPATCHING;
    - upload/start once with deployment_attempt_id;
    - return FAILED_NO_EFFECT, EFFECT_CONFIRMED or IN_DOUBT;
→ no participant prepare may run after external dispatch
```

For this graph, the execution-result participant's
`prepare_depends_on` contains every reversible artifact/enrollment/resource/
audit/trace source but excludes the deployment effect, so its validation is
complete before dispatch. Its `commit_depends_on` contains that same set plus
the `DeploymentExternalEffectParticipant` registration. Consequently hidden
result commit can consume the confirmed deployment/resource receipt without
placing any prepare operation after the irreversible frontier.

There is no provider re-entry and no partial provider-owned prepare API.
`ExecutionCommitCoordinator.prepare_reversible_all()` walks the reversible
dependency graph once; only its subsequent `dispatch_terminal_effect()` crosses
the terminal frontier.
`MARK_ENROLLMENT_EMBEDDED` exists only inside the already durable, pre-registered
enrollment participant. Thus a crash cannot occur between an untracked direct
mark and participant registration.

If deployment start is known STARTED, coordinator chooses `COMMIT_DECIDED` and
durably records the receipt at the no-return point and rolls forward. If
dispatch may have happened but the receipt is unknown, the
external-effect participant returns `ParticipantInDoubtReceiptV2`, coordinator
persists `IN_DOUBT`, and recovery invokes only `probe_attempt()`.

Commit/finalization:

```text
COMMIT_ENROLLMENT_DEPLOYMENT
    → enrollment reservation becomes COMMITTED_HIDDEN;

participant commit
    → local deployment becomes COMMITTED_HIDDEN;

FINALIZE_ENROLLMENT_DEPLOYMENT
    → enrollment reservation becomes finalized for the bound deployment;

participant finalize_visibility
    → deployment lifecycle owner becomes active;

coordinator final COMMITTED
    → execution result/resource refs become normally visible.
```

`QUERY_ENROLLMENT_DEPLOYMENT` is the only reconciliation read and never repeats
mark/prepare/commit/finalize.

Daemon deployment mirror remains an outbox projection and never owns the live
handle.

## 16.4A. Exact enrollment participant receipts

`core/c2/enrollment_models.py` is created in PR-15 and modified here. Exact
models:

```python
class EnrollmentParticipantState(str, Enum):
    REGISTERED = "registered"
    PREPARED = "prepared"
    COMMITTED_HIDDEN = "committed_hidden"
    FINALIZED = "finalized"
    ABORTED = "aborted"
    IN_DOUBT = "in_doubt"


@dataclass(frozen=True)
class EnrollmentEmbeddedReceipt:
    receipt_id: str
    enrollment_ref: str
    enrollment_revision: int
    build_reservation_id: str
    artifact_draft_ref: SensitiveArtifactDraftRefV2
    artifact_sealed_record_digest: str
    artifact_integrity_tag: SensitiveIntegrityTagV2
    artifact_binding_digest: str
    deployment_ref: str
    mission_id: str
    subject_id: str


@dataclass(frozen=True)
class EnrollmentPrepareReceipt:
    receipt_id: str
    transaction_id: str
    embedded: EnrollmentEmbeddedReceipt
    deployment_request_digest: str
    participant_revision: int
    state: Literal[EnrollmentParticipantState.PREPARED]
```

The concrete cross-process control participant is exact and executor-owned:

```python
class C2EnrollmentTransactionParticipant(ExecutionCommitParticipant):
    participant_id: str
    transaction_id: str
    participant_kind: Literal[ParticipantKindV2.CROSS_PROCESS_CONTROL]

    def prepare(
        self,
        request: ParticipantPrepareRequestV2,
    ) -> ParticipantPrepareOutcomeV2: ...

    def commit(
        self,
        request: ParticipantCommitRequestV2,
    ) -> ParticipantCommitReceiptV2: ...

    def finalize_visibility(
        self,
        prepare_receipt: ParticipantPrepareReceiptV2,
        commit_receipt: ParticipantCommitReceiptV2,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantFinalizeReceiptV2: ...

    def rollback(
        self,
        receipt: ParticipantPrepareReceiptV2 | None,
        operation: ParticipantOperationContextV2,
    ) -> ParticipantRollbackReceiptV2: ...

    def reconcile(
        self,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantReconcileResultV2: ...
```

Its `prepare()` resolves the staged `C2EnrollmentDeploymentPlanV1`, performs the
idempotent embedded transition and deployment reservation, persists the exact
`EnrollmentEmbeddedReceipt`/`EnrollmentPrepareReceipt`, and wraps their durable
reference in the generic coordinator receipt. Commit/finalize/rollback/reconcile
map only to the closed enrollment control operations from PR-14. Providers never
receive or construct this participant.

Provider code never creates either receipt and never calls mark/prepare. The
participant prepare call creates both idempotently from the staged plan. A
conflicting artifact/digest/deployment/mission binding fails closed.

Required tests:

```text
test_deploy_provider_only_stages_and_registers_plans
test_deploy_provider_never_calls_prepare_all
test_enrollment_mark_occurs_only_inside_registered_participant_prepare
test_enrollment_participant_registered_before_any_daemon_transition
test_enrollment_participant_implements_exact_commit_protocol
test_provider_cannot_construct_or_call_enrollment_participant
test_enrollment_participant_prepare_called_once_by_coordinator
test_participant_dependency_orders_artifact_enrollment_effect
test_deployment_effect_prepare_runs_remote_start_once
test_deployment_effect_unknown_receipt_returns_in_doubt
test_deploy_result_contains_canonical_resource_and_artifact_drafts
test_enrollment_models_are_created_in_pr15_and_modified_in_pr16
test_no_partial_prepare_resume_api_is_exposed_to_provider
```

## 16.5. `c2_cleanup`

Canonical execution classification:

```text
execution_node_kind=LEAF
provider_transport=IN_PROCESS
```

Backend selected from canonical resource owner, never caller input:

```text
DEPLOYMENT → main-process DeploymentStore cleanup backend
CHANNEL    → daemon-owned C2ControlClient cleanup
ENROLLMENT → daemon-owned revoke
TASK       → daemon-owned cancel
```

Deployment cleanup uses persisted closed cleanup recipe and access session. Daemon receives mirror-close event after local state transition; it does not perform the deployment cleanup itself.

Cleanup is a mutating, potentially uncertain external effect; it is not a direct
provider call. PR-16 owns:

```python
class C2CleanupEffectOutcomeV1(str, Enum):
    CLEANED = "cleaned"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"


C2CleanupResourceKindV1: TypeAlias = Literal[
    ManagedResourceKind.C2_CHANNEL,
    ManagedResourceKind.C2_ENROLLMENT,
    ManagedResourceKind.C2_TASK,
    ManagedResourceKind.DEPLOYMENT,
]


class C2CleanupAttemptStateV1(str, Enum):
    RESERVED = "reserved"
    DISPATCHING = "dispatching"
    CLEANED = "cleaned"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"
    RECONCILING = "reconciling"


@dataclass(frozen=True)
class C2CleanupPlanV1:
    schema_version: Literal["1.0"]
    transaction_id: str
    participant_id: str
    resource_ref: str
    expected_revision: int
    resource_kind: C2CleanupResourceKindV1
    lifecycle_owner: str
    reason: C2CleanupReason
    mission_id: str
    subject_id: str
    cleanup_attempt_id: str
    cleanup_recipe_ref: str | None
    request_digest: str
    idempotency_digest: str


@dataclass(frozen=True)
class C2CleanupAttemptRecordV1:
    transaction_id: str
    participant_id: str
    cleanup_attempt_id: str
    resource_ref: str
    plan_digest: str
    state: C2CleanupAttemptStateV1
    backend_probe_token: str | None
    revision: int


@dataclass(frozen=True)
class C2CleanupEffectReceiptV1:
    transaction_id: str
    participant_id: str
    cleanup_attempt_id: str
    resource_ref: str
    request_digest: str
    outcome: C2CleanupEffectOutcomeV1
    participant_revision: int
    backend_probe_token: str | None
    remote_effect_ref: str | None
    receipt_digest: str


@dataclass(frozen=True)
class C2CleanupEffectProbeV1:
    transaction_id: str
    participant_id: str
    cleanup_attempt_id: str
    resource_ref: str
    request_digest: str
    outcome: C2CleanupEffectOutcomeV1
    observed_revision: int | None
    backend_probe_token: str | None
    probe_digest: str


@dataclass(frozen=True)
class C2CleanupBackendRequestV1:
    plan: C2CleanupPlanV1
    expected_attempt_revision: int
    backend_probe_token: str | None


class C2CleanupBackend(Protocol):
    def cleanup(
        self,
        request: C2CleanupBackendRequestV1,
    ) -> C2CleanupEffectReceiptV1: ...
    def probe_cleanup_attempt(
        self,
        request: C2CleanupBackendRequestV1,
    ) -> C2CleanupEffectProbeV1: ...


class C2CleanupExternalEffectParticipant(ExecutionCommitParticipant):
    participant_id: str
    transaction_id: str
    participant_kind: Literal[ParticipantKindV2.EXTERNAL_EFFECT]
    effect_kind: Literal[ExternalEffectKindV2.RESOURCE_CLEANUP]

    def prepare(
        self,
        request: ParticipantPrepareRequestV2,
    ) -> ParticipantPrepareOutcomeV2: ...
    def commit(
        self,
        request: ParticipantCommitRequestV2,
    ) -> ParticipantCommitReceiptV2: ...
    def finalize_visibility(
        self,
        prepare_receipt: ParticipantPrepareReceiptV2,
        commit_receipt: ParticipantCommitReceiptV2,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantFinalizeReceiptV2: ...
    def rollback(
        self,
        receipt: ParticipantPrepareReceiptV2 | None,
        operation: ParticipantOperationContextV2,
    ) -> ParticipantRollbackReceiptV2: ...
    def reconcile(
        self,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantReconcileResultV2: ...
```

The provider only stages the plan, stages the reversible local lifecycle-state
change and registers `ExternalEffectKindV2.RESOURCE_CLEANUP` as the terminal
participant. It never calls a backend/client. All reversible participants
prepare first. Daemon resources use idempotent `CLEANUP_DAEMON_RESOURCE` plus
`QUERY_C2_RESOURCE`; deployment uses backend `cleanup_attempt_id` plus
`probe_cleanup_attempt`. `CLEANED` forces COMMIT_DECIDED, `FAILED_NO_EFFECT`
permits abort, and `UNKNOWN` enters IN_DOUBT/probe-only. Store enforces UNIQUE
cleanup attempt identity and exact request-digest replay.

`ExecutionCommitParticipantRegistry` has the exact mapping
`RESOURCE_CLEANUP + C2CleanupPlanV1 -> C2CleanupExternalEffectParticipant`.
The participant persists `RESERVED` before dispatch and `DISPATCHING` before
calling the backend. All receipt/probe transaction, participant, attempt,
resource, request-digest, revision and probe-token fields are recomputed and
matched to the record. The stable backend idempotency identity is
`SHA-256(transaction_id || participant_id || cleanup_attempt_id || plan_digest)`.
UNKNOWN always becomes durable IN_DOUBT and only `probe_cleanup_attempt()` may
run; CLEANED forces COMMIT_DECIDED; FAILED_NO_EFFECT permits abort.

`c2_cleanup` никогда не подтверждает результаты. Operator result acknowledgement выполняется исключительно через administrative `ACK_RESULTS` и `ResultAckRequestV1`.

## 16.6. Transaction/idempotency rules

```text
c2_enroll/task/DNS resources are PENDING during prepare and COMMITTED_HIDDEN during participant commit; daemon finalize may make them usable only after durable local COMMIT_DECIDED, while the local result remains hidden until local COMMITTED; a crash between these markers is mandatory roll-forward
c2_deploy local resource/artifact/sensitive/result commit coordinated by ExecutionCommitCoordinator
external remote start has durable PENDING journal before side effect
c2_cleanup terminal transitions idempotent
```

## 16.6A. C2 deployment idempotency, exactly-once remote start and `IN_DOUBT`

`ActionRequestV2.idempotency_key` is mandatory for `c2_deploy`.

`DeploymentStore` enforces:

```text
UNIQUE(mission_id, subject_id, action_id, idempotency_key)
UNIQUE(deployment_attempt_id)
```

Request digest includes target, source/rebinding binding, channel, enrollment,
access session, profile, method, mission and subject.

Before any upload/start side effect allocate and persist the exact models owned
by `core/c2/deployment_attempts.py` (PR-16):

```python
class DeploymentAttemptState(str, Enum):
    RESERVED = "reserved"
    UPLOADING = "uploading"
    START_DISPATCHING = "start_dispatching"
    STARTED = "started"
    UNKNOWN_EFFECT = "unknown_effect"
    FAILED_NO_EFFECT = "failed_no_effect"
    RECONCILING = "reconciling"


class DeploymentProbeOutcome(str, Enum):
    NOT_STARTED = "not_started"
    STARTED = "started"
    FAILED_NO_EFFECT = "failed_no_effect"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class DeploymentAttemptRecord:
    transaction_id: str
    deployment_attempt_id: str
    deployment_ref: str
    request_digest: str
    state: DeploymentAttemptState
    backend_probe_token: str | None
    revision: int


@dataclass(frozen=True)
class DeploymentStartReceipt:
    schema_version: Literal["1.0"]
    deployment_attempt_id: str
    deployment_ref: str
    state: Literal[DeploymentAttemptState.STARTED]
    backend_probe_token: str
    remote_effect_ref: str
    started_at: float
    receipt_digest: str


@dataclass(frozen=True)
class DeploymentAttemptProbe:
    schema_version: Literal["1.0"]
    deployment_attempt_id: str
    deployment_ref: str
    outcome: DeploymentProbeOutcome
    backend_probe_token: str | None
    remote_effect_ref: str | None
    observed_at: float
    probe_digest: str
```

Exact invariants:

```text
STARTED receipt requires non-empty backend_probe_token and remote_effect_ref
probe STARTED requires remote_effect_ref
NOT_STARTED/FAILED_NO_EFFECT require remote_effect_ref=None
UNKNOWN never authorizes retry or rollback
all receipt/probe IDs must equal the persisted DeploymentAttemptRecord
receipt/probe digest is recomputed from canonical fields before state transition
```

The executor-owned `ExecutionCommitCoordinator` has the matching durable
`IN_DOUBT` branch. Independent stores do not pretend to provide a cross-store
atomic write: the external-effect participant first persists the dispatch
journal/attempt outcome, then CASes the coordinator. Recovery consults the
journal even when the last coordinator record is `PREPARING`, making the ordered
writes crash-reconcilable. A shared database implementation may perform both in
one local transaction.

Backend protocol:

```python
@dataclass(frozen=True)
class DeploymentBackendStartRequestV1:
    transaction_id: str
    participant_id: str
    deployment_attempt_id: str
    deployment_ref: str
    target: str
    method: C2DeploymentMethod
    prepared_artifact_stream_ref: str
    artifact_binding_digest: str
    access_session_operation_ref: str
    request_digest: str
    backend_probe_token: str | None


@runtime_checkable
class PreparedSensitiveArtifactStreamV1(Protocol):
    @property
    def stream_ref(self) -> str: ...
    def read_into_protected_channel(
        self,
        *,
        backend_request_digest: str,
    ) -> int: ...
    def close(self) -> None: ...


@runtime_checkable
class DeploymentAccessSessionOperationV1(Protocol):
    @property
    def operation_ref(self) -> str: ...
    def close(self) -> None: ...


@runtime_checkable
class DeploymentParticipantMaterialResolverV1(Protocol):
    def resolve_access_session(
        self,
        *,
        plan: DeploymentStartPlanV1,
        checkout_recovery_ref: CheckoutRecoveryRefV2,
        operation: ParticipantOperationContextV2,
        fence: ExecutionFinalizationFenceV2,
    ) -> DeploymentAccessSessionOperationV1: ...
    def open_prepared_artifact(
        self,
        *,
        plan: DeploymentStartPlanV1,
        artifact_dependency: DependencyPrepareBindingV2,
        operation: ParticipantOperationContextV2,
        fence: ExecutionFinalizationFenceV2,
    ) -> PreparedSensitiveArtifactStreamV1: ...


@dataclass(frozen=True)
class DeploymentBackendProbeRequestV1:
    transaction_id: str
    participant_id: str
    deployment_attempt_id: str
    deployment_ref: str
    request_digest: str
    backend_probe_token: str | None


class DeploymentBackend(Protocol):
    def start(
        self,
        request: DeploymentBackendStartRequestV1,
    ) -> DeploymentStartReceipt: ...

    def probe_attempt(
        self,
        request: DeploymentBackendProbeRequestV1,
    ) -> DeploymentAttemptProbe: ...


class DeploymentExternalEffectParticipant(ExecutionCommitParticipant):
    participant_id: str
    transaction_id: str
    participant_kind: Literal[ParticipantKindV2.EXTERNAL_EFFECT]
    effect_kind: Literal[ExternalEffectKindV2.DEPLOYMENT_START]

    def prepare(
        self,
        request: ParticipantPrepareRequestV2,
    ) -> ParticipantPrepareOutcomeV2: ...
    def commit(
        self,
        request: ParticipantCommitRequestV2,
    ) -> ParticipantCommitReceiptV2: ...
    def finalize_visibility(
        self,
        prepare_receipt: ParticipantPrepareReceiptV2,
        commit_receipt: ParticipantCommitReceiptV2,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantFinalizeReceiptV2: ...
    def rollback(
        self,
        receipt: ParticipantPrepareReceiptV2 | None,
        operation: ParticipantOperationContextV2,
    ) -> ParticipantRollbackReceiptV2: ...
    def reconcile(
        self,
        operation: ParticipantOperationContextV2,
        finalization_fence: ExecutionFinalizationFenceV2,
    ) -> ParticipantReconcileResultV2: ...
```

Registry mapping is exact:
`DEPLOYMENT_START + DeploymentStartPlanV1 -> DeploymentExternalEffectParticipant`.
No generic effect participant dispatches an open payload.

The participant is constructed with the exact
`DeploymentParticipantMaterialResolverV1`; it never performs a global
session/artifact lookup. Immediately before start, the resolver reopens the
checkout-bound access-session operation and the transaction-private PREPARED
sensitive artifact identified by the plan plus the artifact prepare-dependency
receipt.
Both handles are bound to the participant operation deadline and the current
EFFECT_DISPATCH fence. The artifact streams only through a protected channel;
the backend request carries opaque operation/stream refs, never a path or
plaintext. The participant closes both handles in `finally`. Restart uses the
same checkout/draft/dependency evidence and probe never reacquires material or
restarts upload. Revoked/mismatched checkout, tag, sealed digest, dependency
receipt or fence fails before backend dispatch.

Semantics:

```text
- durable attempt record exists before upload/start;
- same idempotency key + same digest returns/reconciles the same attempt;
- same key + different digest returns idempotency_conflict;
- timeout/disconnect after dispatch records UNKNOWN_EFFECT before returning and
  then IN_DOUBT; a crash between records is detected from START_DISPATCHING;
- IN_DOUBT forbids rollback of enrollment/artifact/deployment reservations and forbids another remote start;
- reconciliation calls probe_attempt() only;
- probe STARTED adopts the existing effect and persists COMMIT_DECIDED;
- probe FAILED_NO_EFFECT or NOT_STARTED persists ABORT_DECIDED and then permits rollback/revocation;
- probe UNKNOWN remains IN_DOUBT and requires continued or explicit operator reconciliation;
- a retrying start is allowed only after NOT_STARTED and a new fenced attempt transition;
- concurrent identical requests execute at most one start side effect;
- deployment_attempt_id is propagated to remote marker/process metadata where supported.
```

Tests:

```text
test_deployment_attempt_state_exact_values
test_deployment_start_receipt_exact_fields
test_deployment_attempt_probe_exact_fields
test_deployment_receipt_probe_ids_match_persisted_attempt
test_deploy_requires_idempotency_key
test_deploy_same_key_same_digest_replays
test_deploy_same_key_different_digest_conflicts
test_concurrent_deploy_replay_starts_once
test_deployment_attempt_id_persisted_before_start
test_deploy_timeout_after_dispatch_ordered_journal_is_crash_recoverable
test_in_doubt_never_rolls_back_enrollment_or_artifact
test_unknown_effect_never_restarts_automatically
test_probe_started_adopts_existing_effect_and_commits
test_probe_failed_no_effect_aborts_and_rolls_back
test_probe_not_started_allows_fenced_retry
test_probe_unknown_remains_in_doubt
test_deploy_restart_reconciles_existing_attempt_by_probe
test_cleanup_provider_only_stages_plan_and_never_calls_backend
test_cleanup_reversible_participants_prepare_before_effect
test_cleanup_same_attempt_is_idempotent
test_cleanup_unknown_enters_in_doubt_and_probes_only
test_cleanup_failed_no_effect_aborts
test_cleanup_confirmed_forces_commit_decided
test_cleanup_task_cancel_is_not_result_acknowledgement
```

## Acceptance

```text
c2_enroll mounted=true
EnrollmentEmbeddedReceipt/EnrollmentPrepareReceipt/EnrollmentParticipantState have one exact owner
DeploymentAttemptState/DeploymentStartReceipt/DeploymentAttemptProbe have one exact owner
c2_task mounted=true and V12-only
c2_deploy mounted=true with main DeploymentStore owner
c2_cleanup mounted=true as owner-aware LEAF/IN_PROCESS provider
no daemon ownership of deployment handle
no direct CLI task/enroll/deploy/cleanup client path
```

## Required tests

```text
test_enroll_all_manual_and_acl_gates
test_enroll_idempotent_atomic_issue
test_enroll_daemon_resource_hidden_until_commit_decision_and_finalize
test_task_daemon_resource_hidden_until_commit_decision_and_finalize
test_enroll_refs_only_and_secret_redaction

test_task_requires_v12_capabilities
test_task_requires_advertised_operation_payload_and_result_schemas
test_task_never_creates_command
test_task_idempotent_no_duplicate
test_task_compiler_selects_advertised_payload_and_result_schemas
test_task_compiler_emits_v12_envelope
test_task_compiler_never_emits_command_field
test_cli_queue_task_uses_action_executor

test_deploy_build_and_prebuilt_sources
test_deploy_reserves_build_checkout_before_deployment_ref
test_deploy_allocates_deployment_ref_before_build_or_verify
test_deploy_constructs_and_passes_c2_artifact_build_binding
test_deploy_computes_digest_before_enrollment_prepare
test_staged_c2_artifact_contains_artifact_participant_registration_ref
test_enrollment_participant_depends_on_exact_artifact_participant
test_artifact_participant_registered_before_enrollment_participant
test_deploy_calls_enrollment_prepare_exactly_once
test_prebuilt_binding_verified_before_enrollment_prepare
test_deploy_requires_bound_enrollment
test_deploy_main_process_canonical_owner
test_deploy_daemon_mirror_not_owner
test_deploy_remote_start_journal_before_effect
test_deploy_late_sensitive_failure_rolls_back
test_deploy_mirror_failure_outbox_retry
test_deploy_restart_reconciliation
test_deploy_unknown_effect_does_not_repeat_remote_start
test_deploy_backend_probe_attempt_used_for_reconciliation
test_deploy_missing_cleanup_session_marks_orphaned

test_cleanup_deployment_uses_local_owner
test_cleanup_channel_uses_daemon_owner
test_cleanup_backend_not_caller_selectable
test_cleanup_terminal_idempotency
test_cleanup_task_only_cancels_and_never_acknowledges_results
test_result_ack_only_through_ack_results_application_service
test_all_four_approval_parent_child_use_semantics
test_all_four_finally_cleanup_paths
test_all_four_sensitive_canary_absent
```

## Definition of done

```text
18/20 mounted
four placeholders removed
single deployment lifecycle owner enforced
C2 lifecycle provider E2E green
```

---

# PR-17. Подключение `dns_c2_channel` concrete leaf

## Цель

Подключить daemon-owned DNS channel как retained managed resource через V2 typed leaf.

## CREATE

```text
core/c2/channel_manager.py
core/c2/channel_models.py
core/c2/channel_reconciler.py
tests/test_dns_c2_channel_provider.py
tests/test_c2_channel_manager.py
tests/test_c2_channel_reconciliation.py
tests/integration/test_dns_c2_channel_provider_e2e.py
```

## MODIFY

```text
core/actions/adapters_c2.py
core/actions/input_contracts.py
core/actions/provider_mounts.py
core/actions/readiness_probes.py
core/actions/provider_results.py
core/actions/executor.py
core/c2/channels/dns.py
core/c2/client.py
core/c2/control_models.py
core/c2/control_commands.py
core/c2/control_transactions.py
core/c2/control_rbac.py
core/c2/daemon.py
core/c2/db_backend.py
core/c2/event_store.py
core/c2/resources.py
tests/test_dns_channel_coverage.py
tests/test_c2_daemon_coverage.py
tests/test_action_adapters_new.py
tests/test_high_risk_action_contracts.py
```

## Canonical execution classification

```text
execution_node_kind=LEAF
provider_transport=LOCAL_DAEMON_IPC
```

## Реализация

1. Adapter is V2 `C2IPCActionAdapter` with `DNSC2ChannelInputV2`.
2. Executor resolves authenticated principal, mission, approval and
   `approved_c2_scope`; extracts `TargetRole.PRIMARY` and `TargetRole.LISTEN`.
3. Validate DNS domain, record type, UDP bind address/port and mission/approval
   scope. Port availability is a request precondition, not global readiness.
4. After atomic checkout, reserve the approval attempt and perform the final
   readiness recheck; unavailable releases the pending attempt, otherwise start
   consumes one use.
5. The adapter does not call `CREATE_DNS_CHANNEL` or any daemon creation handler.
6. It canonical-encodes an exact DNS prepare payload, stages it through
   `stage_participant_payload(...)`, obtains its internal registration ref, and
   registers one
   `CrossProcessResourceParticipantRegistrationPayloadV2` with resource kind
   `DeferredManagedResourceRequestV2(C2_CHANNEL, ...)` and explicit-finalize
   visibility; it never fabricates a local transient ID.
   The cross-process spec depends on the staged payload registration.
7. `register()` returns one `CrossProcessResourceRegistrationResultV2`; the
   adapter returns its `resource_draft_ref` in `C2ProviderResult`.
8. During coordinator reversible prepare,
   `C2DaemonResourceParticipant.prepare()`
   sends `PREPARE_C2_RESOURCE`. Daemon `ChannelManager.bind_pending()` synchronously:
   ```text
   socket(AF_INET/AF_INET6, SOCK_DGRAM)
   → bind() in caller thread
   → actual bound endpoint
   → retain non-serving socket; no receive loop, parser, response, fact or task
   ```
   UDP never calls `listen()`.
9. Successful prepare leaves the channel `PENDING` and hidden.
10. `COMMIT_C2_RESOURCE` moves it to `COMMITTED_HIDDEN`; it is still filtered
    from ordinary lookup.
11. `FINALIZE_C2_RESOURCE_VISIBILITY` starts the receive loop, passes a
    running/health barrier, moves it to `ACTIVE` and returns the exact finalize
    ACK. Packets before this transition receive no response and emit no state.
    Only afterward may the local coordinator persist final `COMMITTED` and
    publish the local result ref.
12. Bind failure during PREPARE closes the socket and has no visible resource.
    After `COMMIT_DECIDED`, finalize-start failure must not abort or close an
    otherwise retained bound socket: it remains
    `ExecutionProgressReportV2(RECONCILIATION_PENDING)` and retries
    start/health roll-forward, or reaches `FAILED_RECONCILIATION` without false
    ACTIVE publication.
13. A daemon restart necessarily loses UDP file descriptors. `QUERY_C2_RESOURCE`
    is read-only and never creates a second logical row. The startup reconciler
    CAS-acquires one `(resource_ref, daemon_instance_id)` epoch lease and may
    rebind the same persisted endpoint at most once per daemon epoch, then resume
    the hidden/finalized phase. Rebind failure remains
    `ExecutionProgressReportV2(RECONCILIATION_PENDING)` until recovery or
    reaches the exact terminal FAILED_RECONCILIATION mapping; it never
    publishes false ACTIVE or allocates a new ref.
14. Daemon owns the listener. Main process stores only the transaction-bound
    draft/frozen metadata. Invocation cleanup closes only transient IPC.
15. `c2_cleanup` closes the committed channel later.
16. Set `mounted=true` only after participant/finalization E2E is green.

## Acceptance

```text
dns_c2_channel mounted=true
no direct CREATE_DNS_CHANNEL path
one participant prepare creates one DNS resource
synchronous UDP bind before prepare receipt
hidden commit before explicit finalization
local result not published before daemon finalization ACK
daemon owns listener and channel survives invocation cleanup
```

## Обязательные тесты

```text
test_dns_channel_success_returns_resource_draft
test_dns_channel_invalid_domain
test_dns_channel_invalid_record_type
test_dns_channel_port_bounds
test_dns_channel_bind_scope_denied
test_dns_channel_approval_bind_scope_denied
test_dns_channel_non_operator_denied
test_dns_channel_missing_approval_denied
test_dns_channel_stage_disabled_denied
test_dns_channel_port_in_use_request_precondition
test_dns_channel_readiness_changes_after_checkout
test_dns_provider_never_calls_create_dns_channel
test_dns_provider_registers_one_cross_process_participant
test_dns_prepare_binds_synchronously
test_dns_prepare_socket_is_non_serving
test_dns_packets_before_finalize_receive_no_response_or_state
test_dns_udp_startup_never_calls_listen
test_dns_commit_remains_hidden
test_dns_finalize_visibility_ack_precedes_local_result
test_dns_pending_reconciled_after_restart_without_second_logical_resource
test_dns_restart_rebinds_same_endpoint_at_most_once_per_daemon_epoch
test_dns_finalize_failure_after_commit_decision_rolls_forward_without_close
test_dns_channel_retained_after_invocation_cleanup
test_dns_channel_explicit_cleanup_closes_listener
test_dns_channel_audit_redacted
test_dns_channel_e2e_loopback_nonprivileged_port
```

## Definition of done

```text
19/20 mounted
DNS channel lifecycle E2E green
PENDING reconciliation green
```

# PR-18. Подключение `c2_channel_create` composite router

## Цель

Подключить transport router с обязательным child executor re-entry, derived `ChildIngressLease`, shared approval graph lease и без direct C2 client/daemon/provider path.

## CREATE

```text
tests/test_c2_channel_create_router.py
tests/test_c2_transport_catalog.py
tests/integration/test_c2_channel_create_router_e2e.py
```

## MODIFY

```text
core/actions/adapters_c2.py
core/actions/composite_execution.py
core/c2/transport_catalog.py
core/actions/provider_mounts.py
core/actions/provider_results.py
core/actions/executor.py
core/actions/target_extraction.py
core/auth/approval_leases.py
core/ai/planner.py
core/ai/pipeline_planning.py
tests/test_action_adapters_new.py
tests/test_high_risk_action_contracts.py
tests/test_router_reentry_contract.py
```

## Canonical execution classification

```text
execution_node_kind=COMPOSITE_ROUTER
provider_transport=CHILD_EXECUTOR
```

## Реализация

1. Adapter:
   ```text
   adapter_api_version=2
   protocol=TypedCompositeRouterV2
   methods=check_bound, route_bound, verify_bound
   input=C2ChannelCreateInputV2
   ```
2. `manual_gate` читается только из parent `ActionDescriptorV2`.
3. Parent executor выполняет:
   ```text
   authenticated ingress checkout
   ingress-derived principal resolution
   mission resolution
   approval execution lease resolution
   trusted fact decoding
   target extraction
   router readiness
   parent action/stage authorization
   no material checkout/open and no concrete approval attempt
   ```
4. Parent selection/authorization вызывает только `authorize_router_step(...)`; `reserve_attempt(...)` не вызывается и approval uses не расходуются.
5. `C2TransportCatalog` initially:
   ```text
   DNS → c2:dns_c2_channel
   ```
6. Catalog entry frozen:
   ```python
   C2TransportRoute(
       transport=C2Transport.DNS,
       child_action_id="c2:dns_c2_channel",
       child_input_schema_id="octopus:input:dns_c2_channel:2.0",
   )
   ```
7. Router не импортирует:
   ```text
   core.c2.client
   core.c2.daemon
   core.c2.channels.dns
   ```
8. Router не вызывает:
   ```text
   C2ControlClient
   daemon handler
   DNSChannel
   reference resolver/checkout
   material resolver
   ```
9. Router только:
   ```text
   validates closed transport enum
   resolves child action ID
   builds child typed input
   creates only ChildExecutionSpecV2
   calls only `context.child_execution.run_selected_child(spec=...)`
   ```
10. The executor facade creates request ID, inherits mission/approval/fact refs,
    derives `ChildIngressLease`, narrows lineage/budget and constructs the private
    `ChildExecutionBridge`; router cannot supply any of those values.
11. Executor-created child `ActionRequestV2` содержит только canonical DTO fields:
    ```text
    new request_id
    same mission_ref
    same approval_ref
    same opaque precondition fact refs
    derived child idempotency key when required
    child-specific closed typed input carrying the logical target
    ```
    `parent_execution_id` не входит в child request; parent relation хранится
    только в executor-owned `ExecutionLineage` и `ChildExecutionBridge`.
    `_run_v2_internal` validates all §4.8A action/request/lease/lineage equalities
    before any child catalog/policy lookup.
12. Internal non-serializable `ChildExecutionBridge` содержит:
    ```text
    derived ChildIngressLease bound to child request_id, parent execution ID and execution graph
    same execution_graph_id
    same approval_graph_lease; child receives its own ApprovalAttemptLease only after leaf selection
    parent execution ID
    selected child action ID
    ```
13. Router/caller/planner не может создать, получить или serialize bridge.
14. Parent не передаёт child trusted snapshots/material:
    ```text
    descriptor/mount spec
    readiness snapshot
    principal snapshot
    mission snapshot
    approval snapshot
    fact snapshots
    reference snapshots
    material bundle
    ```
15. Child executor заново:
    ```text
    resolves descriptor/mount spec
    checks out and consumes the derived ChildIngressLease, which resolves the same underlying ingress session
    derives principal from ingress
    resolves mission/approval snapshots
    validates parent-child approval graph
    decodes facts
    extracts child targets
    runs child readiness
    authorizes child action/stage
    atomically checks out child resources
    reserves child attempt as PENDING
    rechecks child readiness
    releases before start on unavailable, otherwise starts atomically
    invokes dns leaf
    ```
15. Approval grant обязан разрешать:
    ```text
    parent action=c2_channel_create
    child action=dns_c2_channel
    parent and child command_and_control stage
    logical target
    bind/listen endpoint
    transport operation
    ```
16. Use semantics:
    ```text
    parent router selection → 0 uses
    child denied/unavailable before attempt → 0 uses
    selected concrete child reserve_attempt → start → exactly 1 use
    ```
17. При `max_uses=1` один execution graph может начать максимум один concrete child attempt.
18. Child не получает новый approval budget и не создаёт новый approval lease.
19. После concrete child attempt automatic fallback на другой active transport запрещён.
20. Если parent разрешён, child запрещён:
    ```text
    child denial propagated
    no provider call
    no approval use
    ```
21. Result — exact `CompositeProviderResult`:
    ```text
    child_action_id
    child_execution_id
    child_result_ref
    ```
    Channel refs are published by the child result referenced by `child_result_ref`; parent/graph IDs, approval state, lifecycle and decision trace remain outside provider result.
22. Новый transport нельзя добавить без:
    ```text
    concrete child identity
    child descriptor
    mount spec
    readiness probe
    closed typed DTO
    target extractor
    RBAC action
    approval graph mapping
    integration test
    ```
23. `ProviderMountSpec.mounted=true` выставить только после router and child E2E green.

## Acceptance

```text
c2_channel_create mounted=true
router does not call client/daemon/provider directly
principal always derived from the child-bound ChildIngressLease over the same validated ingress session
parent consumes zero approval uses
selected child consumes exactly one use
child re-resolves ACL/facts/readiness/policy
parent/child/approval trace complete
```

## Обязательные тесты

```text
test_c2_router_dns_selection
test_c2_router_unknown_transport_rejected
test_c2_router_child_reentry
test_c2_router_child_new_request_id
test_c2_router_action_argument_request_bridge_ids_must_match
test_c2_router_request_id_must_match_child_lease
test_c2_router_lineage_ids_must_match_child_lease
test_c2_router_identity_mismatch_fails_before_approval_or_provider
test_c2_router_bridge_not_serializable
test_c2_router_child_uses_derived_child_ingress_lease
test_c2_router_child_re_resolves_principal_from_ingress
test_c2_router_child_shares_approval_graph_not_attempt_lease
test_c2_router_child_cannot_mint_approval_budget
test_c2_router_parent_consumes_zero_approval_uses
test_c2_router_child_consumes_one_approval_use
test_c2_router_max_uses_one_blocks_second_child_attempt
test_c2_router_denied_before_attempt_consumes_zero_uses
test_c2_router_unavailable_before_attempt_consumes_zero_uses
test_c2_router_child_re_resolves_acl
test_c2_router_child_redecodes_facts
test_c2_router_child_reextracts_targets
test_c2_router_child_readiness_failure
test_c2_router_child_policy_denial
test_c2_router_parent_approval_without_child_permission_denied
test_c2_router_child_permission_without_parent_graph_permission_denied
test_c2_router_no_fallback_after_child_attempt
test_c2_router_no_client_import
test_c2_router_no_daemon_import
test_c2_router_no_dns_provider_import
test_c2_router_preserves_parent_child_trace
test_c2_router_returns_child_channel_ref
test_c2_router_composite_result_has_only_canonical_fields
test_c2_router_e2e_dns
```

## Definition of done

```text
20/20 mounted
router approval/ingress re-entry E2E green
all direct-path architecture gates green
```

---
# PR-19. Registry cleanup, doctor и provider E2E gates

## Цель

Удалить временный unmounted слой, зафиксировать 20/20 и запретить повторное появление обходных execution paths.

## MODIFY

```text
core/tools/quarantined.py
core/tools/manual_actions.py
core/tools/registry.py
core/actions/catalog.py
core/actions/provider_mounts.py
core/actions/models.py
core/actions/executor.py
core/cli/doctor.py
README.md
docs/architecture/action-lifecycle.md
docs/architecture/contracts-and-ownership.md
docs/architecture/current-system-map.md
docs/architecture/provider-selection.md
.github/workflows/ci.yml
.github/workflows/nightly.yml
```

## Семантические удаления (не file ledger)

```text
provider_not_configured placeholders для 20 identities
disabled typed shadow identities
production NullProvider
production FakeProvider
legacy provider fields из V2/shared runtime paths
duplicate declarative V2 manual_gate/execution_node_kind outside canonical
semantic binding или duplicate runtime copy outside exact descriptor projection
старый _send_to_daemon
direct mutating C2 client calls из CLI
```

## Raw facade

Все 20 raw names:

```text
typed_action_required
```

## Doctor output

```text
Provider                 Configured Mounted Available Typed Raw ManualGate
pivot_remote_forward     yes        yes     yes       yes   no  yes
...
payload_keying           yes        yes     yes       yes   no  yes
```

Источники колонок:

```text
Configured/Mounted/Typed/Raw → ProviderMountSpec
ManualGate                   → ActionDescriptorV2
Available                    → dynamic readiness probe
```

Не выводить `authorized` без request fixture.

Добавить:

```text
octopus doctor action <action> --fixture <file>
```

Request doctor выполняет dry-run executor resolution без material reveal и показывает:

```text
configured
mounted
initial readiness
principal resolution
mission resolution
approval resolution
manual gate
stage gate
fact preconditions
reference ACL
extracted targets
authorized
executable
```

Формула:

```text
executable = configured && mounted && available && authorized
```

## Architecture gates

Добавить обязательные tests:

```text
ActionDescriptorV2 — единственный V2 manual_gate owner
ProviderMountSpec — единственный V2 mounted owner
LegacyActionDescriptorV1 wiring ограничен только V1 compatibility path
V2 caller не передаёт canonical state
V2 caller не передаёт raw facts
V2 targets извлекаются executor-owned registry
mission/approval/reference scopes use TargetScopeSnapshot and one TargetScopePolicy
PR file ledger has exactly one CREATE owner per path
material выдаётся только checkout coordinator
all V2 provider calls receive one BoundProviderInvocationContext
sensitive handles have a one-shot transaction staging contract
child re-entry enforces action/request/lease/lineage equality before lookup
readiness recheck существует перед every V2 invocation
provider execution protected outer finally
resource commit выполняется после ingestion/result preparation
96 V1 adapters используют compatibility path
routers используют child ActionExecutor
child action/request/lease/lineage identity invariants are fail closed
C2 outbound socket path единственный
CLI operational C2 mutations используют ActionExecutor; administrative ACK/PURGE/MANAGE/SYNC используют authenticated C2ApplicationService
principal authority derives from authenticated ingress handle
router parent/child approval use semantics are single-consumption
sensitive ingestion participates through an executor-owned commit participant
V12 agent wire contains operation_id/payload, not command
builder cannot auto-issue or accept arbitrary enrollment token
deployment lifecycle owner is main DeploymentStore
production C2 service has static UID/GID and compatible socket group/mode
LIST_RESULTS is non-destructive and ACK_RESULTS is separate mutation
result ACK model is separate from task delivery acknowledgement
root-owned first-admin bootstrap and revisioned grant sync/revocation exist
C2 enrollment participates in deployment transaction through durable participant
deployment UNKNOWN_EFFECT never repeats remote start automatically
DNS channel ACTIVE requires synchronous bind confirmation
operational/admin C2 routing is split between ActionExecutor and C2ApplicationService
legacy provider/provider_mounted migration inventory has zero canonical runtime consumers
```

## E2E lanes

```text
provider-payload-e2e
provider-kerberos-e2e
provider-ad-credential-e2e
provider-ad-remote-e2e
provider-pivot-e2e
provider-c2-control-e2e
provider-c2-lifecycle-e2e
provider-dns-channel-e2e
provider-router-reentry-e2e
provider-resource-lifecycle-e2e
provider-cleanup-failure-e2e
provider-approval-gates-e2e
provider-readiness-race-e2e
provider-reference-checkout-race-e2e
provider-idempotency-recovery-e2e
legacy-96-adapter-regression-e2e
provider-ingress-authentication-e2e
provider-router-approval-max-uses-e2e
provider-sensitive-transaction-rollback-e2e
c2-agent-v12-wire-e2e
c2-builder-enrollment-migration-e2e
c2-deployment-owner-cleanup-e2e
c2-static-service-identity-e2e
c2-results-list-ack-e2e
```

## Final assertions

```python
mounts = PROVIDER_MOUNT_REGISTRY.snapshots()
specs = tuple(mount.spec for mount in mounts)
descriptors = {descriptor.action_id: descriptor for descriptor in action_catalog.descriptors()}

assert len(specs) == 20
assert len({mount.revision for mount in mounts}) == 20
assert len({mount.mount_digest for mount in mounts}) == 20
assert all(PROVIDER_MOUNT_REGISTRY.assert_current(mount) is None for mount in mounts)
assert all(spec.configured for spec in specs)
assert all(spec.mounted for spec in specs)
assert all(spec.typed_action_supported for spec in specs)
assert not any(spec.raw_command_supported for spec in specs)

assert all(descriptors[spec.action_id].manual_gate for spec in specs)
```

Single-owner assertions:

```python
assert "manual_gate" not in ProviderMountSpec.__dataclass_fields__
assert "execution_node_kind" not in ProviderMountSpec.__dataclass_fields__
assert "mounted" not in ActionDescriptorV2.__dataclass_fields__
assert "provider" not in ActionDescriptorV2.__dataclass_fields__
assert "provider_mounted" not in ActionDescriptorV2.__dataclass_fields__
assert "execution_node_kind" in ActionDescriptorV2.__dataclass_fields__
assert "provider" in LegacyActionDescriptorV1.__dataclass_fields__
assert "provider_mounted" in LegacyActionDescriptorV1.__dataclass_fields__
```

Reference runtime:

```python
assert all(readiness_registry.probe(mount).available for mount in mounts)
```

Compatibility:

```python
assert action_catalog.identity_count == 116
assert action_catalog.v1_adapter_count == 96
assert action_catalog.v2_provider_identity_count == 20
```

## Acceptance

```text
0 provider_not_configured
0 unmounted identities
0 unconfigured typed providers
0 production NullProvider
0 production FakeProvider
0 duplicate provider-state owners
0 direct operational C2 mutation paths outside ActionExecutor
0 direct administrative C2 client calls outside C2ApplicationService
20/20 reference-runtime readiness
96 existing adapters regression-green
0 V2/shared runtime consumers of LegacyActionDescriptorV1.provider/provider_mounted
V12 typed agent task wire green
static production C2 service identity green
non-destructive result read/explicit ack green
```

---

# PR-20. Repository-wide transitive typing и migration существующего import-aware gate

## Цель

Устранить global `follow_imports=skip`/`ignore_missing_imports=true`, мигрировать существующий `quality/mypy-import-aware.ini` и все его consumers без создания параллельного третьего typing path.

## CREATE

```text
scripts/quality/mypy_gate.py
scripts/quality/mypy_config_inventory.py
quality/mypy-invocation-partitions.json
typings/README.md
quality/mypy-overrides.json
tests/test_typing_configuration.py
tests/test_provider_type_ownership.py
tests/test_mypy_import_aware_migration.py
tests/test_mypy_invocation_partitioning.py
tests/test_mypy_migration_freeze.py
```

`scripts/quality/mypy_gate.py` является новым файлом.

## MODIFY

```text
docs/architecture/typed-providers-implementation-plan-v6.13.md
pyproject.toml
.github/workflows/ci.yml
README.md
docs/quality/static-analysis-baseline.md
docs/quality/ci-and-vendor-integrity.md
tests/test_quality_gates.py
requirements/dev.txt
requirements/locks/manifest.json
requirements/locks/linux-x86_64/cp310/test.txt
requirements/locks/linux-x86_64/cp310/full.txt
requirements/locks/linux-x86_64/cp311/test.txt
requirements/locks/linux-x86_64/cp311/full.txt
requirements/locks/linux-x86_64/cp312/test.txt
requirements/locks/linux-x86_64/cp312/full.txt
```

`requirements/dev.txt` pins `mypy==2.3.0`; the gate rejects a runtime mypy
version that differs from the dev input, every regenerated lock or the freeze
manifest.

The two reserved tokens are permitted only inside the matching PR-20
CREATE/MODIFY fences while `provider_plan_ledger_gate validate
--phase=planning` runs. Before A1 no migration manifest exists. After A1, that
planning validation additionally requires manifest state FROZEN or MIGRATING.
Each token is the final nonblank fence line and contributes zero paths.
`validate --phase=final` and state COMPLETE reject either token. Authorized
paths are inserted once, in POSIX lexical order, immediately before the matching
token. On a clean A0 tree, `mypy_gate.py freeze --rewrite-plan`
records every diagnostic path as a candidate in the manifest but does not add
all candidates to MODIFY. Before touching an existing candidate,
`authorize-modify PATH` verifies its blob still equals the A0 baseline, replaces
the MODIFY sentinel with `PATH` plus the sentinel, and requires the plan+
manifest authorization commit before source editing. A missing-import stub is
likewise added before creation with `authorize-stub`, which verifies
PATH is absent, under `typings/`, and corresponds to a frozen missing-import
diagnostic. Finalization removes both sentinels. The plan remains the
authoritative exact CREATE/MODIFY ledger; the generated manifest is subordinate
deterministic evidence and must render byte-for-byte to the same path blocks.

## GENERATE

```text
quality/mypy-migration-freeze.json
```

## DELETE

```text
quality/mypy-import-aware.ini
```

The final PR-20 outcome is deletion, not generation or indefinite compatibility.
The file may exist during Phases A–F on the working branch, but the merged PR
must remove it after every consumer is migrated to `mypy_gate.py`/`pyproject.toml`.

## 20.1. Inventory all current consumers

Before edits, inventory exact references to:

```text
quality/mypy-import-aware.ini
python -m mypy
follow_imports
ignore_missing_imports
mypy config paths in docs/tests/CI
```

Known current consumers include:

```text
.github/workflows/ci.yml
README.md
docs/quality/static-analysis-baseline.md
docs/quality/ci-and-vendor-integrity.md
tests/test_quality_gates.py
```

Inventory output becomes a checked allowlist. Missing/new consumers fail CI.
For this gate, a stale consumer is a live executable/configuration/documentation
invocation that selects the deleted ini. This plan's normative history/DELETE
entry and test identifier names are classified as non-consumer evidence; live
README/docs command snippets are not exempt. A golden classifier test fixes this
distinction so the inventory neither becomes impossible nor hides a real caller.

## 20.2. Dual-gate migration phases

Current:

```text
pyproject.toml: broad files, follow_imports=skip, ignore_missing_imports=true
quality/mypy-import-aware.ini: small strict leaf list, follow_imports=normal, ignore_missing_imports=False
CI invokes both
```

Migration (`parent_pr19_commit` and `freeze_base_commit` are distinct):

```text
Phase A0: record parent_pr19_commit; create/pin the final gate/config on top of it
Phase A1: on clean freeze_base_commit=A0_HEAD, discover/freeze the complete
          first-party universe, module identities, partitions and diagnostics
Phase B: use only mypy_gate.py + final pyproject settings to authorize and fix
         exact diagnostic paths; do not expand the legacy ini
Phase C: preserve full transitive coverage and discharge every diagnostic
Phase D: verify final effective settings/module ownership in pyproject.toml
Phase E: CI invokes only mypy_gate.py
Phase F: update README/docs/tests consumers
Phase G: delete quality/mypy-import-aware.ini only after inventory reports zero stale consumers
```

The compatibility file is temporary only during migration and is deleted in the
same PR before merge. No generated compatibility copy remains in the final tree.

Exact migration sequence:

```text
A0: pin mypy==2.3.0, add only the gate/config/partition/control files, enable
    the final effective strict config, regenerate six explicit dev-derived locks
    and manifest; every A0-created Python/test file must already pass that
    strict config before the clean control-plane commit and can never become a
    diagnostic MODIFY candidate because it has no PR-19 blob
A1: run `mypy_gate.py freeze --rewrite-plan` on clean A0 HEAD; commit the
    canonical `quality/mypy-migration-freeze.json` plus this plan only if its
    canonical sentinel rendering changed
B-E: modify only exact authorized MODIFY paths; `authorize-modify` may add a newly
    affected path only under the frozen/emergent diagnostic rule below, while
    its Git blob still equals the A0 baseline blob; the plan+manifest extension
    is committed before editing that source and retroactive authorization of an
    already changed path is rejected
F: require zero strict diagnostics in every deterministic partition and switch
   CI to the sole gate
G: update consumers, delete the legacy ini, set manifest state COMPLETE and
   reject sentinels/migration state/stale consumers/nonzero diagnostics
```

Official stub packages and dependency changes are resolved in A0 before the
freeze. Any later change to `requirements/dev.txt`, the cp310/full lock or lock
manifest invalidates A1 and requires a clean re-freeze before any further source
edit; diagnostics may never be rebaselined after source modification.

Freeze A1 records the A0 blob OID for every discovered first-party source, not
only error-bearing files. The immutable `diagnostics[]` entries contain
`id,path,line,column,end_line,end_column,code,severity,message,hint,
partition_ids`; `candidate_paths[]` contain
`path,freeze_base_blob_oid,diagnostic_ids`. Paths are repo-relative POSIX,
nulls are normalized, and repeated transitive diagnostics are deduplicated by
the canonical tuple excluding `partition_ids`, whose sorted values are then
aggregated. `id` is SHA-256 of that canonical tuple JSON. The immutable
baseline diagnostic tuple digest is never replaced or rebaselined.

Freeze JSON is timestamp-free canonical JSON and contains exact
`schema_version`, state, `parent_pr19_commit`, `freeze_base_commit`, mypy/Python
versions, cp310/full-lock and lock-manifest digests, effective config/discovery/
partition/module-map digests, sorted discovered sources/stubs, the diagnostics
and candidates above,
sorted authorized CREATE/MODIFY paths with baseline blob OIDs and diagnostic
code/counts, and the normalized diagnostic tuple digest. The final diff gate
requires
`changed_existing_python_paths == static_existing_python_modify_paths ∪ authorized_modify_paths`
and
`new_python_or_stub_paths == static_python_create_paths ∪ authorized_create_paths`,
zero Python deletions, plan blocks equal manifest rendering, and zero remaining
diagnostics. Inventory is evidence, never a suppression baseline.
An authorized path that is later reverted must be removed with `deauthorize`
before COMPLETE; the command refuses removal while another manifest entry
depends on that authorization.

## 20.3. `mypy_gate.py`

Commands:

```text
python scripts/quality/mypy_gate.py check
python scripts/quality/mypy_gate.py inventory
python scripts/quality/mypy_gate.py freeze --parent-pr19 COMMIT --freeze-base COMMIT --rewrite-plan
python scripts/quality/mypy_gate.py authorize-modify --path PATH --diagnostic-id ID --reason ERROR_CODE_OR_root_cause_definition
python scripts/quality/mypy_gate.py authorize-stub --path typings/PACKAGE/MODULE.pyi --module MODULE --diagnostic-id ID --owner OWNER --upstream-package DIST --tested-version-range RANGE --reason REASON --removal-condition TEXT --review-date YYYY-MM-DD
python scripts/quality/mypy_gate.py deauthorize --path PATH
python scripts/quality/mypy_gate.py verify-overrides
python scripts/quality/mypy_gate.py verify-config-consumers
python scripts/quality/mypy_gate.py finalization-ready
python scripts/quality/mypy_gate.py complete --rewrite-plan
```

Each metadata-mutating command requires a clean worktree and changes only this
plan plus `quality/mypy-migration-freeze.json`; `authorize-stub` and stub
deauthorization additionally update `quality/mypy-overrides.json` with owner,
upstream/version, reason, removal condition and review date. It refuses a source/stub change
in the same commit, a baseline-blob mismatch, an unknown diagnostic or a path
outside its exact mode. Source/stub creation/editing occurs only in a later
commit after the ledger authorization is durable.
For a clean A0-baseline definition file that does not itself emit the diagnostic,
`--reason root_cause_definition` is permitted only when the manifest records the
affected frozen diagnostic IDs plus a discovered import/symbol dependency edge.
Unknown or unlinked root-cause paths fail closed and require an explicit reviewed
plan amendment; this is not a general path escape hatch.

`authorize-modify` accepts either an immutable A1 diagnostic ID for its frozen
error-bearing path, or an emergent diagnostic that the canonical partitions
reproduce at a clean current HEAD while the target blob still equals its A0
blob. For the latter, the manifest records the normalized diagnostic tuple,
`first_seen_commit`, and a discovered module/symbol dependency edge to an
already authorized changed path. Emergent evidence extends the migration record
but never replaces the A1 set/digest. A diagnostic that is neither frozen nor
currently reproducible fails closed. `authorize-stub` atomically changes plan,
freeze manifest and overrides metadata; deauthorizing a stub removes its
override only when no other authorized stub references that entry.

```python
class MypyMigrationStateV1(str, Enum):
    FROZEN = "frozen"
    MIGRATING = "migrating"
    COMPLETE = "complete"
```

Only FROZEN→MIGRATING→COMPLETE is legal once A1 creates the manifest. Before A1
the two ledger sentinels are valid only under the PR-1 ledger parser's
`--phase=planning`; afterward they require FROZEN/MIGRATING. They are not limited
to A1. `finalization-ready` is read-only.
`complete --rewrite-plan` requires a clean tree, pinned tool/lock/config digests,
zero diagnostics in every partition, checked==discovered sources/stubs, exact
actual-diff==authorized-ledger sets, zero live legacy-config consumers and the
legacy ini absent; it atomically removes both sentinels and sets COMPLETE in
plan+manifest. Final CI `check` rejects a non-COMPLETE state or any sentinel.

Checks:

```text
listed paths exist
CREATE/MODIFY classification is correct
no contradictory module ownership
no first-party ignore_missing_imports override
no new follow_imports=skip scope
strict/equivalent error-code set is complete
overrides have owner/reason/expiry/removal condition
consumer inventory matches allowlist
parent PR-19 commit and clean A0 freeze-base commit are separately recorded
frozen A0 source/config/full-lock digests match the migration inventory
all baseline diagnostics are discharged; none is merely allowlisted
final phase has no stale mypy-import-aware.ini reference
```

## 20.4. Strict scope and expansion

Initial strict scope is machine-derived as every Python path created or modified
by PR-1 through PR-19 in the canonical ledger. The following list is only a
human-readable seed and is deliberately non-authoritative:

```text
core/auth/*
core/actions/provider_*
core/actions/provider_state.py
core/actions/adapter_registration.py
core/actions/schema_bindings.py
core/actions/adapter_versions.py
core/actions/bound_adapters.py
core/actions/reference_*
core/actions/reference_types.py
core/actions/materials.py
core/actions/readiness*
core/actions/invocation_scope.py
core/actions/cancellation.py
core/actions/zeroizable_buffers.py
core/actions/execution_commit*.py
core/actions/execution_drafts.py
core/actions/target_extraction.py
core/actions/trusted_facts.py
core/actions/request_v2.py
core/actions/execution_results_v2.py
core/actions/typed_input_decoders.py
core/actions/execution_budget.py
core/actions/provider_call_boundary.py
core/actions/provider_invocation.py
core/sessions.py
core/artifacts.py
core/pivot_routes.py
core/providers/*
core/c2/client.py
core/c2/control_*
core/c2/agent_protocol_v12.py
core/c2/agent_task_*.py
core/c2/result_service.py
core/c2/control_server_identity.py
core/c2/resources.py
core/c2/channel_manager.py
core/c2/channel_reconciler.py
core/c2/deployment*.py
core/c2/enrollment_service.py
```

Then expand:

```text
core/actions
core/execution
core/auth
core/c2
core/credentials.py
core/secrets.py
core/killchain/ad
core/killchain/pivot
core/plugins
core/ai
core/cli
```

Final discovery is repository-wide and machine-derived, not the union of the
lists above. `mypy_gate.py` recursively discovers every first-party `*.py` in:

```text
repository top-level Python files
core/
modules/
plugins/
scripts/
tests/
benchmarks/
```

Only reviewed environment/vendor/artifact roots may be excluded:

```text
.git, .venv, venv, vendor, node_modules, data, build, dist, generated,
.mypy_cache, .pytest_cache, .ruff_cache, __pycache__
```

The gate separately discovers every `typings/**/*.pyi`, including both
top-level `typings/<module>.pyi` and package layouts. Stub module IDs may
correspond only to declared third-party missing-import diagnostics; shadowing a
first-party module is forbidden. Python-source and stub discovery/checked sets
each require exact equality.

The gate compares the discovered normalized path set with the paths actually
checked by mypy and requires exact equality plus
`untyped_first_party_files == 0`. Any additional exclude needs owner, reason,
expiry and removal condition in the override manifest. There is no first-party
per-module `follow_imports=skip`, `ignore_missing_imports=true`, `exclude` or
`disable_error_code` escape hatch.

Final global settings:

```text
python_version="3.10"
platform="linux"
strict=true
follow_imports=normal
ignore_missing_imports=false
mypy_path = "$MYPY_CONFIG_FILE_DIR/typings"
explicit_package_bases=true
namespace_packages=true
disallow_any_unimported=true
disallow_any_generics=true
disallow_incomplete_defs=true
disallow_untyped_defs=true
disallow_untyped_calls=true
disallow_untyped_decorators=true
disallow_subclassing_any=true
check_untyped_defs=true
no_implicit_optional=true
warn_return_any=true
warn_unused_ignores=true
warn_redundant_casts=true
warn_unreachable=true
warn_unused_configs=true
warn_incomplete_stub=true
no_implicit_reexport=true
strict_equality=true
strict_equality_for_none=true
strict_bytes=true
extra_checks=true
show_error_codes=true
pretty=false
```

`strict=true` plus the explicit flags above is the minimum final contract. For
`mypy==2.3.0` the gate owns a checked-in canonical option map including the
exact strict-mode expansion. It parses `[tool.mypy]`, applies that map and
compares resolved values before invocation; it does not rely on unsupported
"effective config" output from mypy. Unknown, duplicate/conflicting or
per-module relaxing settings fail closed, as does a future mypy release that
changes the map without review. No diagnostic baseline, blanket `# type: ignore`,
first-party stub shadowing or per-module relaxation can satisfy PR-20.
Unreviewed explicit `Any` at V2/control-plane DTO and provider boundaries is
separately prohibited by AST/type-ownership ratchets; internal explicit `Any`
remains subject to the pinned normal strict-mypy semantics.

Some current benchmark trees contain standalone modules. The exact initial
partition file is:

```json
{
  "schema_version": 1,
  "default_partition_id": "default",
  "singleton_partitions": [
    {"id": "benchmark-lab-app", "path": "benchmarks/competitors/lab/app.py"},
    {"id": "discovery-lab-v2-app", "path": "benchmarks/competitors/labs/discovery-lab-v2/app.py"},
    {"id": "discovery-lab-v3-app", "path": "benchmarks/competitors/labs/discovery-lab-v3/app.py"}
  ]
}
```

The default partition is discovery minus singleton paths; invocation order is
default then singleton IDs lexically. The JSON permits no flags or excludes.
Using pinned `mypy.find_sources.create_source_list` with the final Options, the
gate freezes repo-relative POSIX `(path,module,relative_base_dir)` BuildSource
tuples and the module-map digest. `lab/app.py` resolves to
`benchmarks.competitors.lab.app`; the v2/v3 files both resolve to `app`, so only
those two are the current duplicate group (the reviewed lab singleton is
harmless). Every duplicate group member must be in a distinct partition;
unknown/missing/repeated paths or any module-map delta fail closed.

Each partition runs from repository root through `sys.executable` with exact
argv `-m mypy --config-file <absolute-root>/pyproject.toml --no-incremental
--no-error-summary --output=json <sorted repo-relative roots>`. The gate clears
`MYPYPATH`, `MYPY_CACHE_DIR` and `MYPY_NUM_WORKERS`. Stdout is UTF-8 JSON Lines,
not one JSON document: only empty lines are ignored; a non-object/schema line,
nonempty unexpected stderr or exit 2 is infrastructure failure. Exit 1 is
accepted only for inventory/freeze and only with valid diagnostic records.
The explicit BuildSource.path union across batches—not JSON diagnostics—is
`checked_first_party_paths`; it equals discovery exactly even for zero-error
files. Imported dependencies may be visited repeatedly but do not change root
ownership.

Freeze A1 and the CI typing lane run on `ubuntu-22.04`, Linux x86_64, exact
CPython 3.10.20, `LC_ALL=C.UTF-8`, `PYTHONHASHSEED=0`, installed with
`requirements/locks/linux-x86_64/cp310/full.txt --require-hashes`; the full
profile supplies every declared dependency. The gate requires CPython,
`sys.version_info[:3] == (3,10,20)`, `sys.platform == "linux"`, and
`platform.machine()` in `{x86_64, AMD64}`, and runs mypy only through
`sys.executable`. The manifest records the exact interpreter/mypy versions,
full-lock SHA-256 and lock-manifest digest. A floating 3.10, local macOS or
partial-venv inventory is invalid.

Canonical local-stub layout:

```text
typings/<module>.pyi
typings/<package>/__init__.pyi
typings/<package>/<module>.pyi
```

Every local stub package has an entry in `quality/mypy-overrides.json` with:

```text
owner
upstream package and pinned/tested version range
reason
source modules covered
removal condition
expiry/review date
```

Third-party libraries use official stubs, local stubs or typed Protocol wrappers. Untyped third-party objects cannot cross control-plane DTO boundaries.

## Acceptance

```text
scripts/quality/mypy_gate.py exists and is sole CI entrypoint
quality/mypy-import-aware.ini is deleted in the final PR-20 tree after all consumers migrate
all previous consumers updated
no stale config references
first-party imports transitive
no global follow_imports=skip
no global ignore_missing_imports=true
no broad suppressions
checked_first_party_paths == discovered_first_party_paths
untyped_first_party_files == 0
strict effective option set complete
PR-1..PR-19 Python ledger paths are a subset of strict checked paths
all frozen Phase-A diagnostics discharged with zero suppression baseline
```

## Tests

```text
test_mypy_gate_file_exists
test_current_consumer_inventory_complete
test_no_stale_import_aware_live_consumer_after_finalization
test_ci_uses_single_mypy_gate_entrypoint
test_global_follow_imports_normal
test_global_ignore_missing_imports_false
test_global_strict_and_equivalent_flags_enabled
test_effective_mypy_config_exact_strict_flags
test_mypy_version_matches_dev_lock_and_freeze
test_final_config_has_no_files_or_exclude
test_discovery_walks_repository_root
test_no_first_party_ignore_override
test_override_entries_have_owner_reason_expiry
test_mypy_path_points_to_typings
test_local_stub_packages_follow_canonical_layout
test_each_stub_has_owner_upstream_version_and_removal_condition
test_stub_removed_when_upstream_typing_is_available
test_v1_v2_adapter_union_exhaustive
test_reference_snapshot_union_exhaustive
test_c2_payload_union_exhaustive
test_provider_mount_state_single_typed_owner
test_strict_scope_paths_exist
test_repository_wide_first_party_discovery_equals_mypy_checked_set
test_pr1_through_pr19_python_ledger_is_in_strict_checked_set
test_duplicate_module_ids_are_deterministically_partitioned_not_excluded
test_every_partition_has_zero_diagnostics
test_partition_batches_are_disjoint
test_partition_union_equals_discovery
test_existing_duplicate_app_modules_are_isolated_singletons
test_new_duplicate_module_fails_closed
test_partition_cannot_change_flags
test_partition_preflight_freezes_buildsource_module_and_base_dir
test_jsonl_diagnostics_reject_non_object_and_nonempty_stderr
test_typing_lane_requires_exact_cp31020_linux_x86_64_full_lock
test_phase_a_inventory_pins_parent_pr19_and_clean_a0_freeze_base
test_baseline_diagnostics_are_not_an_allowlist
test_freeze_is_deterministic
test_authorization_commands_render_plan_ledger_exactly
test_authorize_modify_requires_unmodified_freeze_base_blob
test_freeze_cannot_retroactively_authorize_modified_path
test_stub_path_is_absent_under_typings_and_frozen_before_create
test_final_plan_has_no_pr20_generated_path_sentinels
test_changed_python_paths_are_ledgered
test_complete_authorized_paths_equal_actual_python_diff
test_complete_state_has_zero_diagnostics
test_untyped_first_party_files_is_zero
test_first_party_excludes_are_exact_and_reviewed
test_all_discovered_sources_compile_under_python310
test_forward_referencing_v2_modules_use_future_annotations_or_string_refs
test_dev_requirement_change_regenerates_test_and_full_all_targets
test_lock_manifest_updated_for_dev_change
test_six_dev_lock_paths_and_manifest_changed
```

---

## 14. Полная последовательность PR

```text
PR-1  Canonical state ownership, provider manifest и legacy provider/provider_mounted migration
PR-2  Authenticated ingress invocation lease и atomic approval budget
PR-3  Dynamic readiness и immediate pre-call recheck
PR-4  Trusted facts, target extraction и atomic checkout
PR-5  Guaranteed finally cleanup и transactional sensitive outcome commit
PR-6  Closed V2 DTO, operation catalogs и target schemas
PR-7  Adapter API V2 compatibility, typed results и bound bases
PR-8  payload_keying
PR-9  Kerberos providers
PR-10 AD credential providers
PR-11 AD remote-execution leaves
PR-12 ad_remote_execution composite re-entry
PR-13 Pivot providers
PR-14 C2ControlClient, static service identity и result-control semantics
PR-15 Agent protocol V12 и enrollment-aware builder/implant migration
PR-16 c2_enroll, c2_task, c2_cleanup, c2_deploy
PR-17 dns_c2_channel leaf
PR-18 c2_channel_create composite re-entry
PR-19 Registry cleanup, doctor и E2E gates
PR-20 Repository-wide transitive typing и mypy-import-aware migration
```

---

## 15. Финальные критерии

### 15.1. Canonical ownership

```text
schema/semantic matrices — единственный declarative owner IDs, aliases, fact IDs
and node/check/verify semantics
ActionDescriptorV2 — единственная immutable runtime projection этих semantics
ProviderMountSpec — единственный owner V2 configured/mounted/provider wiring
LegacyActionDescriptorV1.provider/provider_mounted разрешены только в V1 compatibility path
V2/shared runtime не читает legacy provider fields
ProviderMountRegistry содержит только 20 V2 identities и отклоняет 96 V1 IDs
нет ActionDescriptorV2.provider или ActionDescriptorV2.provider_mounted
нет ProviderMountSpec.manual_gate или ProviderMountSpec.execution_node_kind
нет canonical runtime provider/provider_mounted consumers
нет duplicate trusted state
unknown alias or required_fact_type_id fails catalog construction
```

### 15.2. Static/dynamic provider state

```text
20/20 configured=true
20/20 mounted=true
20/20 typed_action_supported=true
20/20 descriptors manual_gate=true
20/20 raw_command_supported=false
20/20 available=true в reference runtime
```

### 15.3. Формула исполнимости

Для каждого request:

```text
executable =
    configured
    && mounted
    && available
    && authorized
```

### 15.4. Ingress и approval

```text
principal выводится только из current validated IngressInvocationLease
lease peer/channel/request-bound, single-use, non-serializable
caller cannot supply principal/session authority
router child uses executor-derived child lease
parent router consumes zero approval uses
selected concrete child consumes exactly one use
max_uses enforced atomically across pending+consumed attempts
```

### 15.5. Facts/references/readiness

```text
trusted facts decoded from canonical refs
all nested targets extracted by executor-owned extractor
metadata.reference == authorization.reference
atomic checkout before material
metadata/ACL/fact/approval revisions fenced
initial readiness after coarse authorization and immediate pre-call readiness recheck
specific resource existence remains request precondition
```

### 15.6. Transaction/cleanup

```text
outer finally covers success/exception/timeout/cancellation/late failures
SensitiveObservationIngestor is a transaction participant
secrets/credentials/facts/artifacts/results/audit/resources staged under one durable coordinator
providers receive only restricted staging/participant-registration facades; coordinator alone invokes participant lifecycle
provider execute capabilities share one revocable phase lease and fail after execute returns
provider-visible scope has no transfer/close and provider has no sensitive staging capability
no provisional ref visible before required daemon finalization ACKs and final coordinator COMMITTED marker
V2 provider stages only through BoundProviderInvocationContext.staging
sensitive observation handles can be staged exactly once
failure before external-effect dispatch rolls back; UNKNOWN_EFFECT enters durable IN_DOUBT with probe-only recovery; COMMIT_DECIDED rolls forward only
PENDING resource transaction-owned
ACTIVE retained resources survive InvocationScope
committed ExecutionResultV2 contains no cleanup field; post-finally status lives in InvocationFinalizationRecordV2
finalization is durably persisted or durably queued before a report claims pending
sensitive plaintext uses only one-shot zeroizable buffer capabilities
```

### 15.7. Adapter compatibility

```text
96 existing adapters remain V1 lifecycle with LegacyActionDescriptorV1
20 provider identities use V2 lifecycle with ActionDescriptorV2 + ProviderMountRegistry
catalog retains 116 identities through tagged ActionCatalogEntry union
ProviderMountRegistry contains only the 20 V2 identities
V1 signatures not mass-rewritten
```

### 15.8. C2 control and service identity

```text
only outbound IPC path = C2ControlClient
_send_to_daemon removed
framing = uint32 big-endian
server validates client via SO_PEERCRED on accepted socket
client validates daemon via pinned signed handshake under socket activation
production service uses static octopus-c2 UID/GID
DynamicUser removed from reference unit
socket owner/group/mode compatible with peer ACL
complete RBAC includes LIST/ACK/PURGE results and new C2 actions
idempotency bound to operator+subject+mission+action and atomic with side effect
```

### 15.9. C2 task/enrollment/deployment lifecycle

```text
Go/Python V12 agents use closed typed operation/payload/result wire
operation, payload-schema and result-schema capabilities are persisted and enforced
no V12 raw command execution path
V11 agents cannot receive typed tasks
production builders cannot self-issue enrollment
all builder/implant/stager paths require enrollment checkout
c2_deploy accepts/binds enrollment_ref
main-process DeploymentStore is canonical deployment owner
daemon stores mirror only and never owns deployment handle
c2_cleanup deployment path uses local owner; daemon cleanup only for daemon-owned resources
LIST_RESULTS never mutates/deletes
ACK_RESULTS uses separate ResultAckRequestV1 and never task delivery ACK
PURGE_RESULTS admin/retention mutation
first ADMIN bootstrap is root-owned, non-networked and crash-safe
peer/mission grant sync and revocation are revisioned and ADMIN-only
C2EnrollmentTransactionParticipant is durable across daemon/local transaction boundary
c2_enroll/c2_task/dns_c2_channel use C2DaemonResourceParticipant prepare/hidden-commit/finalize/abort/query and have no direct creation path
deployment allocates deployment_ref, builds or rebinds a new artifact, computes the single full digest, marks enrollment EMBEDDED_IN_ARTIFACT, then performs exactly one enrollment prepare
deployment exactly-once uses deployment_attempt_id, probe_attempt and durable UNKNOWN_EFFECT/IN_DOUBT fencing
enrollment is single-use and orphan build reservations are release/revoke reconciled
DNS UDP PREPARE binds a non-serving socket; receive loop/ACTIVE occurs only in FINALIZE and never calls listen()
c2_cleanup is an idempotent terminal external-effect participant with probe semantics
```

### 15.9A. Cross-process commit and participant contracts

```text
provider-visible/internal participant payload unions and ParticipantRegistrationResultV2 are closed and authority-separated
ProviderParticipantRegistrationFacade.register has one exact union return type
provider-visible registration cannot create result/audit/sensitive/local-store participants
ExecutionCommitCoordinator alone calls prepare/commit/finalize/rollback/reconcile
cross-process resource commit is hidden and requires explicit finalization ACK
local ExecutionResultV2 is not published before daemon finalization ACK
no simultaneous cross-process ACID claim; durability invariant starts at COMMIT_DECIDED
c2_enroll/c2_task/dns_c2_channel have no direct ISSUE/QUEUE/CREATE creation path
c2_deploy remote start is an executor-owned ExternalEffectParticipant
all reversible participants prepare before the sole terminal external effect
MARK_ENROLLMENT_EMBEDDED semantics occur only inside the registered enrollment participant prepare
```

### 15.10. Routers and contracts

```text
ad_remote_execution child re-enters ActionExecutor
c2_channel_create child re-enters ActionExecutor
router cannot call provider/client/daemon/material resolver directly
router receives BoundCompositeRouterContextV2, opens no material and reserves no parent attempt
no channel_options/deployment_profile/arguments dict
ActionRequestV2 and V2InputUnion are introduced exactly once in PR-6 and contain no authority/runtime state
PR-2 contains concrete ExecutionResultV2/ActionExecutionReportV2 but no future-type imports
all 20 action/input/result schema IDs match the normative §2.4 matrix
all material wrappers, state enums and ProviderResult variants have exact fields and one owner
all supporting enums and C2EnrollmentIssueInput have one canonical owner and exact values
no arbitrary command or arbitrary output path
V2 check/verify are descriptor-required, capability-restricted phases
composite child_result_ref is an ExecutionResultRefV2 obtained only from a committed child report
child result helper also requires SUCCEEDED or accepted PARTIAL status
```

### 15.11. Typing and repository migration

```text
core/tools/manual_actions.py created as PR-1 CREATE
scripts/quality/mypy_gate.py created as PR-20 CREATE
quality/mypy-import-aware.ini deleted and all former consumers migrated to the sole mypy gate
all provider/provider_mounted consumers explicitly migrated or legacy-decoder allowlisted
follow_imports=normal
ignore_missing_imports=false
repository-wide transitive mypy
checked first-party path set equals repository discovery and untyped_first_party_files=0
```

### 15.12. Итог

```text
0 provider_not_configured
0 unmounted identities
0 unconfigured typed providers
0 production NullProvider
0 production FakeProvider
0 duplicate canonical-state owners
0 direct operational C2 mutation paths outside ActionExecutor
0 direct administrative C2 client calls outside C2ApplicationService
0 material reveal before atomic checkout
0 provider access to ExecutionCommitCoordinator or participant objects
0 provider calls to participant prepare/commit/finalize/rollback/reconcile
0 provider-visible sensitive staging or private scope transfer/close
0 provider direct imports of stores/coordinator/C2 client outside reviewed backend allowlist
0 immutable-byte sensitive zeroization claims
0 daemon C2 resource committed before local transaction decision
0 DNS packet response/fact/task before visibility finalization
0 V12 raw-command tasks
0 builder self-issued enrollment tokens
0 destructive result reads
0 stale mypy-import-aware consumers
0 V2/shared runtime consumers of LegacyActionDescriptorV1.provider/provider_mounted

Для каждого request:
executable = configured && mounted && available && authorized
```
