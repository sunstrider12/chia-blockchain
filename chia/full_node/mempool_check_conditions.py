import time
from typing import Tuple, Dict, List, Optional, Set
from clvm import SExp
import traceback

from chia.consensus.cost_calculator import NPCResult
from chia.consensus.condition_costs import ConditionCost
from chia.full_node.generator import create_generator_args, setup_generator_args
from chia.types.blockchain_format.coin import Coin
from chia.types.blockchain_format.program import NIL
from chia.types.blockchain_format.sized_bytes import bytes32
from chia.types.coin_record import CoinRecord
from chia.types.condition_with_args import ConditionWithArgs
from chia.types.generator_types import BlockGenerator
from chia.types.name_puzzle_condition import NPC
from chia.util.clvm import int_from_bytes
from chia.util.condition_tools import ConditionOpcode, conditions_by_opcode
from chia.util.errors import Err
from chia.util.ints import uint32, uint64, uint16
from chia.wallet.puzzles.generator_loader import GENERATOR_FOR_SINGLE_COIN_MOD
from chia.wallet.puzzles.rom_bootstrap_generator import get_generator

GENERATOR_MOD = get_generator()


def mempool_assert_announcement(condition: ConditionWithArgs, announcements: Set[bytes32]) -> Optional[Err]:
    """
    Check if an announcement is included in the list of announcements
    """
    announcement_hash = bytes32(condition.vars[0])
    if announcement_hash not in announcements:
        return Err.ASSERT_ANNOUNCE_CONSUMED_FAILED

    return None


def mempool_assert_my_coin_id(condition: ConditionWithArgs, unspent: CoinRecord) -> Optional[Err]:
    """
    Checks if CoinID matches the id from the condition
    """
    if unspent.coin.name() != condition.vars[0]:
        return Err.ASSERT_MY_COIN_ID_FAILED
    return None


def mempool_assert_absolute_block_height_exceeds(
    condition: ConditionWithArgs, prev_transaction_block_height: uint32
) -> Optional[Err]:
    """
    Checks if the next block index exceeds the block index from the condition
    """
    try:
        block_index_exceeds_this = int_from_bytes(condition.vars[0])
    except ValueError:
        return Err.INVALID_CONDITION
    if prev_transaction_block_height < block_index_exceeds_this:
        return Err.ASSERT_HEIGHT_ABSOLUTE_FAILED
    return None


def mempool_assert_relative_block_height_exceeds(
    condition: ConditionWithArgs, unspent: CoinRecord, prev_transaction_block_height: uint32
) -> Optional[Err]:
    """
    Checks if the coin age exceeds the age from the condition
    """
    try:
        expected_block_age = int_from_bytes(condition.vars[0])
        block_index_exceeds_this = expected_block_age + unspent.confirmed_block_index
    except ValueError:
        return Err.INVALID_CONDITION
    if prev_transaction_block_height < block_index_exceeds_this:
        return Err.ASSERT_HEIGHT_RELATIVE_FAILED
    return None


def mempool_assert_absolute_time_exceeds(condition: ConditionWithArgs, timestamp: uint64) -> Optional[Err]:
    """
    Check if the current time in seconds exceeds the time specified by condition
    """
    try:
        expected_seconds = int_from_bytes(condition.vars[0])
    except ValueError:
        return Err.INVALID_CONDITION

    if timestamp is None:
        timestamp = uint64(int(time.time()))
    if timestamp < expected_seconds:
        return Err.ASSERT_SECONDS_ABSOLUTE_FAILED
    return None


def mempool_assert_relative_time_exceeds(
    condition: ConditionWithArgs, unspent: CoinRecord, timestamp: uint64
) -> Optional[Err]:
    """
    Check if the current time in seconds exceeds the time specified by condition
    """
    try:
        expected_seconds = int_from_bytes(condition.vars[0])
    except ValueError:
        return Err.INVALID_CONDITION

    if timestamp is None:
        timestamp = uint64(int(time.time()))
    if timestamp < expected_seconds + unspent.timestamp:
        return Err.ASSERT_SECONDS_RELATIVE_FAILED
    return None


def mempool_assert_my_parent_id(condition: ConditionWithArgs, unspent: CoinRecord) -> Optional[Err]:
    """
    Checks if coin's parent ID matches the ID from the condition
    """
    if unspent.coin.parent_coin_info != condition.vars[0]:
        return Err.ASSERT_MY_PARENT_ID_FAILED
    return None


def mempool_assert_my_puzzlehash(condition: ConditionWithArgs, unspent: CoinRecord) -> Optional[Err]:
    """
    Checks if coin's puzzlehash matches the puzzlehash from the condition
    """
    if unspent.coin.puzzle_hash != condition.vars[0]:
        return Err.ASSERT_MY_PUZZLEHASH_FAILED
    return None


def mempool_assert_my_amount(condition: ConditionWithArgs, unspent: CoinRecord) -> Optional[Err]:
    """
    Checks if coin's amount matches the amount from the condition
    """
    if unspent.coin.amount != int_from_bytes(condition.vars[0]):
        return Err.ASSERT_MY_AMOUNT_FAILED
    return None


def parse_aggsig(args: SExp) -> List[bytes]:
    pubkey = args.first().atom
    args = args.rest()
    message = args.first().atom
    if args.rest().atom != b"":
        raise RuntimeError("too many condition arguments")
    if len(pubkey) != 48:
        raise RuntimeError("invalid pubkey in AGGSIG condition")
    if len(message) > 1024:
        raise RuntimeError("invalid message in AGGSIG condition")
    return [pubkey, message]


def parse_create_coin(args: SExp) -> List[bytes]:
    puzzle_hash = args.first().atom
    args = args.rest()
    amount = args.first().atom
    if args.rest().atom != b"":
        raise RuntimeError("too many condition arguments")
    if len(puzzle_hash) != 32:
        raise RuntimeError("invalid f{name}")
    amount_int = int_from_bytes(amount)
    if amount_int >= 2**64 or amount_int < 0:
        raise RuntimeError("invalid coin amount")
    return [puzzle_hash, amount]


def parse_seconds(args: SExp) -> Optional[List[bytes]]:
    seconds = args.first().atom
    if args.rest().atom != b"":
        raise RuntimeError("too many condition arguments")
    seconds_int = int_from_bytes(seconds)
    # this condition is inherently satisified, there is no need to keep it
    if seconds_int <= 0:
        return None
    if seconds_int >= 2**64:
        raise RuntimeError("invalid timestamp")
    return [seconds]


def parse_height(args: SExp) -> Optional[List[bytes]]:
    height = args.first().atom
    if args.rest().atom != b"":
        raise RuntimeError("too many condition arguments")
    height_int = int_from_bytes(height)
    # this condition is inherently satisified, there is no need to keep it
    if height_int <= 0:
        return None
    if height_int >= 2**32 or height_int < 0:
        raise RuntimeError("invalid height")
    return [height]


def parse_fee(args: SExp) -> List[bytes]:
    fee = args.first().atom
    if args.rest().atom != b"":
        raise RuntimeError("too many condition arguments")
    fee_int = int_from_bytes(fee)
    if fee_int >= 2**64 or fee_int < 0:
        raise RuntimeError("invalid fee")
    return [fee]


def parse_coin_id(args: SExp) -> List[bytes]:
    coin = args.first().atom
    if args.rest().atom != b"":
        raise RuntimeError("too many condition arguments")
    if len(coin) != 32:
        raise RuntimeError("invalid coin ID")
    return [coin]


def parse_hash(args: SExp, name: str) -> List[bytes]:
    h = args.first().atom
    if args.rest().atom != b"":
        raise RuntimeError("too many condition arguments")
    if len(h) != 32:
        raise RuntimeError("invalid f{name}")
    return [h]


def parse_amount(args: SExp) -> List[bytes]:
    amount = args.first().atom
    if args.rest().atom != b"":
        raise RuntimeError("too many condition arguments")
    amount_int = int_from_bytes(amount)
    if amount_int >= 2**64 or amount_int < 0:
        raise RuntimeError("invalid amount")
    return [amount]


def parse_announcement(args: SExp) -> List[bytes]:
    msg = args.first().atom
    if args.rest().atom != b"":
        raise RuntimeError("too many condition arguments")
    if len(msg) > 1024:
        raise RuntimeError("invalid announcement")
    return [msg]


def parse_condition_args(args: SExp, condition: ConditionOpcode) -> Tuple[int, Optional[List[bytes]]]:
    """
    Parse a list with exactly the expected args, given opcode,
    from an SExp into a list of bytes. If there are fewer or more elements in
    the list, raise a RuntimeError. If the condition is inherently true (such as
    a time- or height lock with a negative time or height, the returned list is None
    """
    if condition is ConditionOpcode.AGG_SIG_UNSAFE or condition is ConditionOpcode.AGG_SIG_ME:
        return ConditionCost.AGG_SIG.value, parse_aggsig(args)
    elif condition is ConditionOpcode.CREATE_COIN:
        return ConditionCost.CREATE_COIN.value, parse_create_coin(args)
    elif condition is ConditionOpcode.ASSERT_SECONDS_ABSOLUTE:
        return ConditionCost.ASSERT_SECONDS_ABSOLUTE.value, parse_seconds(args)
    elif condition is ConditionOpcode.ASSERT_SECONDS_RELATIVE:
        return ConditionCost.ASSERT_SECONDS_RELATIVE.value, parse_seconds(args)
    elif condition is ConditionOpcode.ASSERT_HEIGHT_ABSOLUTE:
        return ConditionCost.ASSERT_HEIGHT_ABSOLUTE.value, parse_height(args)
    elif condition is ConditionOpcode.ASSERT_HEIGHT_RELATIVE:
        return ConditionCost.ASSERT_HEIGHT_RELATIVE.value, parse_height(args)
    elif condition is ConditionOpcode.ASSERT_MY_COIN_ID:
        return ConditionCost.ASSERT_MY_COIN_ID.value, parse_coin_id(args)
    elif condition is ConditionOpcode.RESERVE_FEE:
        return ConditionCost.RESERVE_FEE.value, parse_fee(args)
    elif condition is ConditionOpcode.CREATE_COIN_ANNOUNCEMENT:
        return ConditionCost.CREATE_COIN_ANNOUNCEMENT.value, parse_announcement(args)
    elif condition is ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT:
        return ConditionCost.ASSERT_COIN_ANNOUNCEMENT.value, parse_hash(args, "announcement hash")
    elif condition is ConditionOpcode.CREATE_PUZZLE_ANNOUNCEMENT:
        return ConditionCost.CREATE_PUZZLE_ANNOUNCEMENT.value, parse_announcement(args)
    elif condition is ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT:
        return ConditionCost.ASSERT_PUZZLE_ANNOUNCEMENT.value, parse_hash(args, "puzzle announcement")
    elif condition is ConditionOpcode.ASSERT_MY_PARENT_ID:
        return ConditionCost.ASSERT_MY_PARENT_ID.value, parse_coin_id(args)
    elif condition is ConditionOpcode.ASSERT_MY_PUZZLEHASH:
        return ConditionCost.ASSERT_MY_PUZZLEHASH.value, parse_hash(args, "puzzle hash")
    elif condition is ConditionOpcode.ASSERT_MY_AMOUNT:
        return ConditionCost.ASSERT_MY_AMOUNT.value, parse_amount(args)
    else:
        assert False


opcodes: Set[bytes] = set(item.value for item in ConditionOpcode)


def parse_condition(cond: SExp, safe_mode: bool) -> Tuple[int, ConditionWithArgs]:
    total_cost: int = 0
    condition = cond.first().as_atom()
    if condition in opcodes:
        opcode: ConditionOpcode = ConditionOpcode(condition)
        cost, args = parse_condition_args(cond.rest(), opcode)
        cvl = ConditionWithArgs(opcode, args) if args is not None else None
    elif not safe_mode:
        opcode = ConditionOpcode.UNKNOWN
        cvl = ConditionWithArgs(opcode, cond.rest().as_atom_list())
        cost = 0
    else:
        raise RuntimeError("unknown condition")
    return cost, cvl


def get_name_puzzle_conditions(generator: BlockGenerator, max_cost: int, *,
        cost_per_byte: int, safe_mode: bool) -> NPCResult:
    """
    This executes the generator program and returns the coins and their
    conditions. If the cost of the program (size, CLVM execution and conditions)
    exceed max_cost, the function fails. In order to accurately take the size
    of the program into account when calculating cost, cost_per_byte must be
    specified.
    safe_mode determines whether the clvm program and conditions are executed in
    strict mode or not. When in safe/strict mode, unknow operations or conditions
    are considered failures. This is the mode when accepting transactions into
    the mempool.
    """
    try:
        block_program, block_program_args = setup_generator_args(generator)
        max_cost -= len(bytes(generator)) * cost_per_byte
        if max_cost < 0:
            return NPCResult(uint16(Err.BLOCK_COST_EXCEEDS_MAX.value), [], uint64(0))
        if safe_mode:
            clvm_cost, result = GENERATOR_MOD.run_safe_with_cost(max_cost, block_program, block_program_args)
        else:
            clvm_cost, result = GENERATOR_MOD.run_with_cost(max_cost, block_program, block_program_args)

        max_cost -= clvm_cost
        npc_list: List[NPC] = []

        for res in result.first().as_iter():
            conditions_list: List[ConditionWithArgs] = []

            spent_coin_parent_id: bytes32 = res.first().as_atom()
            spent_coin_puzzle_hash: bytes32 = res.rest().first().as_atom()
            spent_coin_amount: uint64 = uint64(res.rest().rest().first().as_int())
            spent_coin: Coin = Coin(spent_coin_parent_id, spent_coin_puzzle_hash, spent_coin_amount)

            for cond in res.rest().rest().rest().first().as_iter():
                cost, cvl = parse_condition(cond, safe_mode)
                max_cost -= cost
                if max_cost < 0:
                    return NPCResult(uint16(Err.BLOCK_COST_EXCEEDS_MAX.value), [], uint64(0))
                if cvl is not None:
                    conditions_list.append(cvl)

            conditions_dict = conditions_by_opcode(conditions_list)
            if conditions_dict is None:
                conditions_dict = {}
            npc_list.append(
                NPC(spent_coin.name(), spent_coin.puzzle_hash, [(a, b) for a, b in conditions_dict.items()])
            )
        return NPCResult(None, npc_list, uint64(clvm_cost))
    except Exception as e:
        print(e)
        traceback.print_exc()
        return NPCResult(uint16(Err.GENERATOR_RUNTIME_ERROR.value), [], uint64(0))


def get_puzzle_and_solution_for_coin(generator: BlockGenerator, coin_name: bytes, max_cost: int):
    try:
        block_program = generator.program
        if not generator.generator_args:
            block_program_args = NIL
        else:
            block_program_args = create_generator_args(generator.generator_refs())

        cost, result = GENERATOR_FOR_SINGLE_COIN_MOD.run_with_cost(
            max_cost, block_program, block_program_args, coin_name
        )
        puzzle = result.first()
        solution = result.rest().first()
        return None, puzzle, solution
    except Exception as e:
        return e, None, None


def mempool_check_conditions_dict(
    unspent: CoinRecord,
    coin_announcement_names: Set[bytes32],
    puzzle_announcement_names: Set[bytes32],
    conditions_dict: Dict[ConditionOpcode, List[ConditionWithArgs]],
    prev_transaction_block_height: uint32,
    timestamp: uint64,
) -> Optional[Err]:
    """
    Check all conditions against current state.
    """
    for con_list in conditions_dict.values():
        cvp: ConditionWithArgs
        for cvp in con_list:
            error: Optional[Err] = None
            if cvp.opcode is ConditionOpcode.ASSERT_MY_COIN_ID:
                error = mempool_assert_my_coin_id(cvp, unspent)
            elif cvp.opcode is ConditionOpcode.ASSERT_COIN_ANNOUNCEMENT:
                error = mempool_assert_announcement(cvp, coin_announcement_names)
            elif cvp.opcode is ConditionOpcode.ASSERT_PUZZLE_ANNOUNCEMENT:
                error = mempool_assert_announcement(cvp, puzzle_announcement_names)
            elif cvp.opcode is ConditionOpcode.ASSERT_HEIGHT_ABSOLUTE:
                error = mempool_assert_absolute_block_height_exceeds(cvp, prev_transaction_block_height)
            elif cvp.opcode is ConditionOpcode.ASSERT_HEIGHT_RELATIVE:
                error = mempool_assert_relative_block_height_exceeds(cvp, unspent, prev_transaction_block_height)
            elif cvp.opcode is ConditionOpcode.ASSERT_SECONDS_ABSOLUTE:
                error = mempool_assert_absolute_time_exceeds(cvp, timestamp)
            elif cvp.opcode is ConditionOpcode.ASSERT_SECONDS_RELATIVE:
                error = mempool_assert_relative_time_exceeds(cvp, unspent, timestamp)
            elif cvp.opcode is ConditionOpcode.ASSERT_MY_PARENT_ID:
                error = mempool_assert_my_parent_id(cvp, unspent)
            elif cvp.opcode is ConditionOpcode.ASSERT_MY_PUZZLEHASH:
                error = mempool_assert_my_puzzlehash(cvp, unspent)
            elif cvp.opcode is ConditionOpcode.ASSERT_MY_AMOUNT:
                error = mempool_assert_my_amount(cvp, unspent)
            if error:
                return error

    return None
