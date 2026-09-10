use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use argent_runtime::{
    actor as actor_arg, args, state, stdlib::core::invocation_uid, Artifact, ArtifactValue, CovenantOutput, EntryCall, TxBuilder,
    TxContext,
};
use blake2b_simd::Params as Blake2bParams;
use kaspa_consensus_core::hashing::sighash::calc_schnorr_signature_hash;
use kaspa_consensus_core::hashing::sighash::SigHashReusedValuesUnsync;
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_consensus_core::tx::{
    CovenantBinding, MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionOutpoint, UtxoEntry,
};
use kaspa_consensus_core::Hash;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey};

use crate::protocol_move::{apply_protocol_move, apply_standard_chess_move, ProtocolMoveSpec, ProtocolState, OFFBOARD};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerKind {
    Pawn,
    Knight,
    Vert,
    Horiz,
    Diag,
    King,
    Castle,
    CastleChallenge,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GameResult {
    WhiteWin,
    BlackWin,
    Draw,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrchestratorError(pub String);

impl std::fmt::Display for OrchestratorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for OrchestratorError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Side {
    White,
    Black,
}

const DEFAULT_MOVE_TIMEOUT: i64 = 600;
const WHITE: i64 = 0;
const BLACK: i64 = 1;
const LIVE: i64 = 0;
const WWIN: i64 = 1;
const BWIN: i64 = 2;
const DRAW: i64 = 3;
const CLEAR: i64 = 0;
const OFFER: i64 = 1;
const CLAIM: i64 = 2;
const SURRENDER: i64 = 3;
const ACCEPT: i64 = 4;
const CLAIMED: i64 = 1;
const DEFENSE: i64 = 2;
const NORMAL: i64 = 3;
const WOFFER: i64 = 4;
const BOFFER: i64 = 5;

fn player_ref_hash(owner_hash: Hash, player_id: Hash) -> Hash {
    hash_pair(owner_hash, player_id)
}

fn hash_pair(left: Hash, right: Hash) -> Hash {
    let left = left.as_bytes();
    let right = right.as_bytes();
    blake2b(&[left.as_slice(), right.as_slice()].concat())
}

impl SigningPlayer {
    pub fn from_seed(name: impl Into<String>, seed: u8) -> Self {
        let name = name.into();
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid deterministic secret key");
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (x_only, _) = keypair.x_only_public_key();
        let pubkey_bytes = x_only.serialize().to_vec();
        let owner_hash = blake2b(&pubkey_bytes);
        Self { name, keypair, pubkey_bytes, owner_hash, player_id: None, player_ref: None }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlayerAccount {
    pub owner_name: String,
    pub owner_hash: Hash,
    pub player_id: Hash,
    pub player_ref: Hash,
    pub value: u64,
    pub open_games: i64,
    pub rating: i64,
    pub games: i64,
    pub wins: i64,
    pub draws: i64,
    pub losses: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OffchainMessageKind {
    GameInvite { proposed_white: String, proposed_black: String },
    InviteAccepted { white: String, black: String },
    GameStarted { white: String, black: String },
    MoveNotice { actor: String, worker: WorkerKind, move_label: String, mv: MoveSpec },
    DrawOffered { actor: String },
    DrawClaimed { actor: String },
    DrawAccepted { actor: String },
    TimeoutClaimAvailable { result: GameResult, worker: WorkerKind, move_label: String },
    SettlementRequest { result: GameResult },
    SettlementNotice { result: GameResult },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OffchainMessage {
    pub from: String,
    pub to: String,
    pub kind: OffchainMessageKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubmittedTx {
    pub action: &'static str,
    pub transaction_id: TransactionId,
    pub input_outpoints: Vec<TransactionOutpoint>,
    pub output_outpoints: Vec<TransactionOutpoint>,
    pub signer_names: Vec<String>,
}

fn submitted_tx(action: &'static str, tx: &Transaction, signer_names: Vec<String>) -> SubmittedTx {
    let transaction_id = tx.id();
    SubmittedTx {
        action,
        transaction_id,
        input_outpoints: tx.inputs.iter().map(|input| input.previous_outpoint).collect(),
        output_outpoints: tx
            .outputs
            .iter()
            .enumerate()
            .map(|(index, _)| TransactionOutpoint::new(transaction_id, index as u32))
            .collect(),
        signer_names,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MoveSpec {
    pub from_x: i64,
    pub from_y: i64,
    pub to_x: i64,
    pub to_y: i64,
    pub promo_piece: i64,
}

impl MoveSpec {
    pub fn new(from_x: i64, from_y: i64, to_x: i64, to_y: i64) -> Self {
        Self { from_x, from_y, to_x, to_y, promo_piece: 0 }
    }

    pub fn with_promotion(from_x: i64, from_y: i64, to_x: i64, to_y: i64, promo_piece: i64) -> Self {
        Self { from_x, from_y, to_x, to_y, promo_piece }
    }

    pub fn label(self) -> String {
        format!("{}{}{}{}", file_char(self.from_x), rank_char(self.from_y), file_char(self.to_x), rank_char(self.to_y))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActualGameSnapshot {
    pub white_player_ref: Hash,
    pub black_player_ref: Hash,
    pub phase: String,
    pub board: Vec<u8>,
    pub turn: Side,
    pub status: i64,
    pub move_timeout: i64,
    pub recent_castle: i64,
    pub draw_state: i64,
    pub move_log: Vec<String>,
}

#[derive(Clone)]
pub struct SigningPlayer {
    pub name: String,
    keypair: Keypair,
    pub pubkey_bytes: Vec<u8>,
    pub owner_hash: Hash,
    pub player_id: Option<Hash>,
    pub player_ref: Option<Hash>,
}

#[derive(Clone)]
struct PlayerStateData {
    owner_hash: Hash,
    player_id: Hash,
    outpoint: TransactionOutpoint,
    value: u64,
    open_games: i64,
    rating: i64,
    games: i64,
    wins: i64,
    draws: i64,
    losses: i64,
}

fn league_source_state(base_rating: i64, admin: Hash) -> BTreeMap<String, ArtifactValue> {
    state! {
        base_rating: base_rating,
        admin: admin,
    }
}

fn player_source_state(state: &PlayerStateData) -> BTreeMap<String, ArtifactValue> {
    state! {
        owner: state.owner_hash,
        player_id: state.player_id,
        open_games: state.open_games,
        rating: state.rating,
        games: state.games,
        wins: state.wins,
        draws: state.draws,
        losses: state.losses,
    }
}

fn state_byte(value: i64) -> u8 {
    u8::try_from(value).expect("bounded Chess state value fits in a byte")
}

fn game_source_state(state: &GameStateData) -> BTreeMap<String, ArtifactValue> {
    state! {
        white_player: state.white_player,
        black_player: state.black_player,
        board: state.board.clone(),
        turn: state_byte(state.turn),
        status: state_byte(state.status),
        move_timeout: state.move_timeout,
        castle_rights: state.castle_rights,
        en_passant_idx: state_byte(state.en_passant_idx),
        pending_src_idx: state_byte(state.pending_src_idx),
        pending_dst_idx: state_byte(state.pending_dst_idx),
        pending_promo: state_byte(state.pending_promo),
        recent_castle: state_byte(state.recent_castle),
        draw_state: state_byte(state.draw_state),
    }
}

fn settle_source_state(white_player: Hash, black_player: Hash, status: i64) -> BTreeMap<String, ArtifactValue> {
    state! {
        white_player: white_player,
        black_player: black_player,
        status: state_byte(status),
    }
}

fn orchestrator_builder_error(context: &'static str) -> impl FnOnce(argent_runtime::BuilderError) -> OrchestratorError {
    move |err| OrchestratorError(format!("{context}: {err}"))
}

#[derive(Clone)]
struct GameStateData {
    white_player: Hash,
    black_player: Hash,
    board: Vec<u8>,
    turn: i64,
    status: i64,
    move_timeout: i64,
    castle_rights: [u8; 4],
    en_passant_idx: i64,
    pending_src_idx: i64,
    pending_dst_idx: i64,
    pending_promo: i64,
    recent_castle: i64,
    draw_state: i64,
    move_log: Vec<String>,
}

#[derive(Clone)]
struct ActiveWorkerState {
    kind: WorkerKind,
    state: GameStateData,
    outpoint: TransactionOutpoint,
}

#[derive(Clone)]
struct ActiveSettleState {
    white_player: Hash,
    black_player: Hash,
    status: i64,
    outpoint: TransactionOutpoint,
}

struct MuxRouteRequest<'a> {
    actor: &'a SigningPlayer,
    game: &'a GameStateData,
    target: &'static str,
    pending: &'a GameStateData,
    mv: MoveSpec,
    termination_action: i64,
}

struct PartialWorkerCommit {
    worker: WorkerKind,
    state: GameStateData,
    outpoint: TransactionOutpoint,
    mv: MoveSpec,
    transactions: Vec<Transaction>,
    submissions: Vec<SubmittedTx>,
}

#[derive(Clone)]
struct LeagueLane {
    outpoint: TransactionOutpoint,
    value: u64,
}

pub struct TxArena {
    artifact: Artifact,
    admin: SigningPlayer,
    league_state: BTreeMap<String, ArtifactValue>,
    league_lanes: Vec<LeagueLane>,
    base_rating: i64,
    covenant_id: Hash,
    players: BTreeMap<String, PlayerStateData>,
    game: Option<GameStateData>,
    game_outpoint: Option<TransactionOutpoint>,
    active_worker: Option<ActiveWorkerState>,
    active_settle: Option<ActiveSettleState>,
    messages: BTreeMap<String, Vec<OffchainMessage>>,
    history: Vec<SubmittedTx>,
    transactions: Vec<Transaction>,
}

#[derive(Clone)]
pub struct TxOrchestrator {
    pub player: SigningPlayer,
    arena: Rc<RefCell<TxArena>>,
}

impl TxOrchestrator {
    pub fn new(name: impl Into<String>, seed: u8, arena: Rc<RefCell<TxArena>>) -> Self {
        Self { player: SigningPlayer::from_seed(name, seed), arena }
    }

    pub fn inbox(&self) -> Vec<OffchainMessage> {
        self.arena.borrow_mut().drain_messages(&self.player.name)
    }

    pub fn register(&mut self) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().register_player(&mut self.player)
    }

    pub fn register_on_lane(&mut self, lane_index: usize) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().register_player_on_lane(&mut self.player, lane_index)
    }

    pub fn send_game_invite(&self, other: &TxOrchestrator) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().send_game_invite(&self.player, &other.player)
    }

    pub fn accept_game_invite(&self, other: &TxOrchestrator) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().accept_game_invite(&self.player, &other.player)
    }

    pub fn start_game(&self, other: &TxOrchestrator) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().start_game(&self.player, &other.player)
    }

    pub fn submit_move(&self, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.arena.borrow_mut().submit_move(&self.player, mv)
    }

    pub fn offer_draw(&self, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.arena.borrow_mut().offer_draw(&self.player, mv)
    }

    pub fn force_move(&self, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.arena.borrow_mut().force_move(&self.player, mv)
    }

    pub fn challenge_castle(&self, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.arena.borrow_mut().challenge_castle(&self.player, mv, false)
    }

    pub fn force_castle_challenge(&self, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.arena.borrow_mut().challenge_castle(&self.player, mv, true)
    }

    pub fn claim_draw(&self) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().claim_draw(&self.player)
    }

    pub fn accept_draw(&self) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().accept_draw(&self.player)
    }

    pub fn surrender(&self) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().surrender(&self.player)
    }

    pub fn claim_timeout(&self) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().claim_timeout(&self.player)
    }

    pub fn request_settlement(&self, other: &TxOrchestrator, result: GameResult) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().request_settlement(&self.player, &other.player, result)
    }

    pub fn settle(&self, other: &TxOrchestrator, result: GameResult) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().settle_game(&self.player, &other.player, result)
    }

    pub fn retire(&self) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().retire_player(&self.player)
    }

    pub fn rebalance(&self, value: u64) -> Result<(), OrchestratorError> {
        self.arena.borrow_mut().rebalance_player(&self.player, value)
    }
}

impl TxArena {
    pub fn new() -> Result<Self, OrchestratorError> {
        let artifact = load_argent_artifact()?;
        let admin = SigningPlayer::from_seed("admin", 0x33);
        let base_rating = 1200;
        let league_state = league_source_state(base_rating, admin.owner_hash);
        let league_output = {
            let builder = TxBuilder::new(&artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
            let funding_outpoint = TransactionOutpoint::new(TransactionId::from_bytes([0x77; 32]), 0);
            let funding_utxo = UtxoEntry::new(1_000, ScriptPublicKey::from_vec(0, vec![0x51]), 0, false, None);
            let context = TxContext::new().input(funding_outpoint, funding_utxo, Vec::new(), 0).actor_genesis_output(
                0,
                "launch::league",
                "League",
                league_state.clone(),
                1_000,
            );
            let tx = builder.build(&context).map_err(orchestrator_builder_error("launch League"))?;
            argent_runtime::CovenantOutput::from_tx(&tx, 0).map_err(orchestrator_builder_error("read League genesis output"))?
        };

        Ok(Self {
            artifact,
            admin,
            league_state,
            league_lanes: vec![LeagueLane { outpoint: league_output.outpoint, value: league_output.utxo.amount }],
            base_rating,
            covenant_id: league_output.covenant_id,
            players: BTreeMap::new(),
            game: None,
            game_outpoint: None,
            active_worker: None,
            active_settle: None,
            messages: BTreeMap::new(),
            history: Vec::new(),
            transactions: Vec::new(),
        })
    }

    pub fn shared() -> Result<Rc<RefCell<Self>>, OrchestratorError> {
        Ok(Rc::new(RefCell::new(Self::new()?)))
    }

    pub fn drain_messages(&mut self, name: &str) -> Vec<OffchainMessage> {
        self.messages.remove(name).unwrap_or_default()
    }

    pub fn history(&self) -> &[SubmittedTx] {
        &self.history
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    pub fn covenant_id(&self) -> Hash {
        self.covenant_id
    }

    pub fn league_lane_count(&self) -> usize {
        self.league_lanes.len()
    }

    pub fn league_lane_values(&self) -> Vec<u64> {
        self.league_lanes.iter().map(|lane| lane.value).collect()
    }

    pub fn player_account_snapshot(&self, player: &SigningPlayer) -> Result<PlayerAccount, OrchestratorError> {
        let player_ref = player.player_ref.ok_or_else(|| OrchestratorError(format!("{} is not registered", player.name)))?;
        self.player_account(player_ref)
    }

    fn owner_name(&self, player_ref: Hash) -> Result<String, OrchestratorError> {
        self.players
            .iter()
            .find_map(|(name, state)| (player_ref_hash(state.owner_hash, state.player_id) == player_ref).then_some(name.clone()))
            .ok_or_else(|| OrchestratorError("missing player owner".to_string()))
    }

    pub fn active_game_snapshot(&self) -> Option<ActualGameSnapshot> {
        self.game
            .as_ref()
            .map(|game| ActualGameSnapshot {
                white_player_ref: game.white_player,
                black_player_ref: game.black_player,
                phase: "mux".to_string(),
                board: game.board.clone(),
                turn: side_from_turn(game.turn),
                status: game.status,
                move_timeout: game.move_timeout,
                recent_castle: game.recent_castle,
                draw_state: game.draw_state,
                move_log: game.move_log.clone(),
            })
            .or_else(|| {
                self.active_worker.as_ref().map(|worker| ActualGameSnapshot {
                    white_player_ref: worker.state.white_player,
                    black_player_ref: worker.state.black_player,
                    phase: format!("worker:{:?}", worker.kind),
                    board: worker.state.board.clone(),
                    turn: side_from_turn(worker.state.turn),
                    status: worker.state.status,
                    move_timeout: worker.state.move_timeout,
                    recent_castle: worker.state.recent_castle,
                    draw_state: worker.state.draw_state,
                    move_log: worker.state.move_log.clone(),
                })
            })
    }

    pub fn rebalance_league(&mut self, lane_index: usize, value: u64) -> Result<(), OrchestratorError> {
        let lane = self
            .league_lanes
            .get(lane_index)
            .cloned()
            .ok_or_else(|| OrchestratorError(format!("missing League lane {lane_index}")))?;
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let lane_utxo = builder
            .covenant_utxo("League", self.league_state.clone(), lane.value, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build League lane UTXO"))?;
        let keypair = self.admin.keypair;
        let public_key = self.admin.pubkey_bytes.clone();
        let context = TxContext::new()
            .actor_input(
                "League",
                self.league_state.clone(),
                EntryCall::new("rebalance")
                    .args_with(move |tx, input_index| args![sign_builder_input(tx, input_index, &keypair), public_key.clone()]),
                lane.outpoint,
                lane_utxo,
                0,
            )
            .actor_output("League", self.league_state.clone(), CovenantBinding::new(0, self.covenant_id), value);
        let tx = builder.build(&context).map_err(orchestrator_builder_error("rebalance League lane"))?;
        let txid = tx.id();
        let submission = submitted_tx("league_rebalance", &tx, vec![self.admin.name.clone()]);
        self.transactions.push(tx);
        self.league_lanes[lane_index] = LeagueLane { outpoint: TransactionOutpoint::new(txid, 0), value };
        self.history.push(submission);
        Ok(())
    }

    pub fn fork_league(&mut self, lane_index: usize, left_value: u64, right_value: u64) -> Result<(), OrchestratorError> {
        let lane = self
            .league_lanes
            .get(lane_index)
            .cloned()
            .ok_or_else(|| OrchestratorError(format!("missing League lane {lane_index}")))?;
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let lane_utxo = builder
            .covenant_utxo("League", self.league_state.clone(), lane.value, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build League lane UTXO"))?;
        let keypair = self.admin.keypair;
        let public_key = self.admin.pubkey_bytes.clone();
        let context = TxContext::new()
            .actor_input(
                "League",
                self.league_state.clone(),
                EntryCall::new("fork")
                    .args_with(move |tx, input_index| args![sign_builder_input(tx, input_index, &keypair), public_key.clone()]),
                lane.outpoint,
                lane_utxo,
                0,
            )
            .actor_output("League", self.league_state.clone(), CovenantBinding::new(0, self.covenant_id), left_value)
            .actor_output("League", self.league_state.clone(), CovenantBinding::new(0, self.covenant_id), right_value);
        let tx = builder.build(&context).map_err(orchestrator_builder_error("fork League lane"))?;
        let txid = tx.id();
        let submission = submitted_tx("league_fork", &tx, vec![self.admin.name.clone()]);
        self.transactions.push(tx);
        self.league_lanes.splice(
            lane_index..=lane_index,
            [
                LeagueLane { outpoint: TransactionOutpoint::new(txid, 0), value: left_value },
                LeagueLane { outpoint: TransactionOutpoint::new(txid, 1), value: right_value },
            ],
        );
        self.history.push(submission);
        Ok(())
    }

    pub fn register_player(&mut self, player: &mut SigningPlayer) -> Result<(), OrchestratorError> {
        self.register_player_on_lane(player, 0)
    }

    pub fn register_player_on_lane(&mut self, player: &mut SigningPlayer, lane_index: usize) -> Result<(), OrchestratorError> {
        let lane = self
            .league_lanes
            .get(lane_index)
            .cloned()
            .ok_or_else(|| OrchestratorError(format!("missing League lane {lane_index}")))?;
        let player_id =
            invocation_uid(&lane.outpoint, b"LeaguePlayerId").map_err(|err| OrchestratorError(format!("derive player ID: {err}")))?;
        let player_ref = player_ref_hash(player.owner_hash, player_id);
        let registered = PlayerStateData {
            owner_hash: player.owner_hash,
            player_id,
            outpoint: lane.outpoint,
            value: 1_000,
            open_games: 0,
            rating: self.base_rating,
            games: 0,
            wins: 0,
            draws: 0,
            losses: 0,
        };
        let executed_tx = {
            let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
            let league_utxo = builder
                .covenant_utxo("League", self.league_state.clone(), lane.value, 0, false, Some(self.covenant_id))
                .map_err(orchestrator_builder_error("build League UTXO"))?;
            let keypair = player.keypair;
            let public_key = player.pubkey_bytes.clone();
            let context = TxContext::new()
                .actor_input(
                    "League",
                    self.league_state.clone(),
                    EntryCall::new("register_player")
                        .args_with(move |tx, input_index| args![sign_builder_input(tx, input_index, &keypair), public_key.clone()]),
                    lane.outpoint,
                    league_utxo,
                    0,
                )
                .actor_output("League", self.league_state.clone(), CovenantBinding::new(0, self.covenant_id), lane.value)
                .actor_output("Player", player_source_state(&registered), CovenantBinding::new(0, self.covenant_id), registered.value);
            builder.build(&context).map_err(orchestrator_builder_error("register player"))?
        };
        let executed_txid = executed_tx.id();
        let submission = submitted_tx("register_player", &executed_tx, vec![player.name.clone()]);
        self.league_lanes[lane_index].outpoint = TransactionOutpoint::new(executed_txid, 0);
        self.transactions.push(executed_tx);

        player.player_id = Some(player_id);
        player.player_ref = Some(player_ref);
        self.players
            .insert(player.name.clone(), PlayerStateData { outpoint: TransactionOutpoint::new(executed_txid, 1), ..registered });
        self.history.push(submission);
        Ok(())
    }

    pub fn send_game_invite(&mut self, white: &SigningPlayer, black: &SigningPlayer) -> Result<(), OrchestratorError> {
        self.require_registered(white)?;
        self.require_registered(black)?;
        self.push_message(
            &black.name,
            OffchainMessage {
                from: white.name.clone(),
                to: black.name.clone(),
                kind: OffchainMessageKind::GameInvite { proposed_white: white.name.clone(), proposed_black: black.name.clone() },
            },
        );
        Ok(())
    }

    pub fn accept_game_invite(&mut self, black: &SigningPlayer, white: &SigningPlayer) -> Result<(), OrchestratorError> {
        self.require_registered(white)?;
        self.require_registered(black)?;
        self.push_message(
            &white.name,
            OffchainMessage {
                from: black.name.clone(),
                to: white.name.clone(),
                kind: OffchainMessageKind::InviteAccepted { white: white.name.clone(), black: black.name.clone() },
            },
        );
        Ok(())
    }

    pub fn start_game(&mut self, white: &SigningPlayer, black: &SigningPlayer) -> Result<(), OrchestratorError> {
        let white_state = self.players.get(&white.name).cloned().ok_or_else(|| OrchestratorError("missing white".to_string()))?;
        let black_state = self.players.get(&black.name).cloned().ok_or_else(|| OrchestratorError("missing black".to_string()))?;

        let mut next_white = white_state.clone();
        next_white.open_games += 1;
        let mut next_black = black_state.clone();
        next_black.open_games += 1;

        let white_ref = white.player_ref.ok_or_else(|| OrchestratorError("white missing player ref".to_string()))?;
        let black_ref = black.player_ref.ok_or_else(|| OrchestratorError("black missing player ref".to_string()))?;
        let opening = GameStateData {
            white_player: white_ref,
            black_player: black_ref,
            board: standard_board(),
            turn: 0,
            status: 0,
            move_timeout: DEFAULT_MOVE_TIMEOUT,
            castle_rights: [1, 1, 1, 1],
            en_passant_idx: OFFBOARD,
            pending_src_idx: OFFBOARD,
            pending_dst_idx: OFFBOARD,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: 3,
            move_log: Vec::new(),
        };
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let white_utxo = builder
            .covenant_utxo("Player", player_source_state(&white_state), white_state.value, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build white Player UTXO"))?;
        let black_utxo = builder
            .covenant_utxo("Player", player_source_state(&black_state), black_state.value, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build black Player UTXO"))?;
        let white_keypair = white.keypair;
        let white_public_key = white.pubkey_bytes.clone();
        let black_keypair = black.keypair;
        let black_public_key = black.pubkey_bytes.clone();
        let context = TxContext::new()
            .actor_input(
                "Player",
                player_source_state(&white_state),
                EntryCall::new("start_game").args_with(move |tx, input_index| {
                    args![
                        sign_builder_input(tx, input_index, &white_keypair),
                        white_public_key.clone(),
                        state_byte(WHITE),
                        DEFAULT_MOVE_TIMEOUT,
                    ]
                }),
                white_state.outpoint,
                white_utxo,
                0,
            )
            .actor_input(
                "Player",
                player_source_state(&black_state),
                EntryCall::new("delegate_start_game").args_with(move |tx, input_index| {
                    args![sign_builder_input(tx, input_index, &black_keypair), black_public_key.clone(), DEFAULT_MOVE_TIMEOUT]
                }),
                black_state.outpoint,
                black_utxo,
                0,
            )
            .actor_output("Player", player_source_state(&next_white), CovenantBinding::new(0, self.covenant_id), next_white.value)
            .actor_output("Player", player_source_state(&next_black), CovenantBinding::new(0, self.covenant_id), next_black.value)
            .actor_output("Mux", game_source_state(&opening), CovenantBinding::new(0, self.covenant_id), 1_000);
        let executed_tx = builder.build(&context).map_err(orchestrator_builder_error("start game"))?;
        let executed_txid = executed_tx.id();
        let submission = submitted_tx("start_game", &executed_tx, vec![white.name.clone(), black.name.clone()]);
        self.transactions.push(executed_tx);

        self.players.insert(white.name.clone(), next_white);
        self.players.insert(black.name.clone(), next_black);
        self.players.get_mut(&white.name).expect("white tracked").outpoint =
            TransactionOutpoint { transaction_id: executed_txid, index: 0 };
        self.players.get_mut(&black.name).expect("black tracked").outpoint =
            TransactionOutpoint { transaction_id: executed_txid, index: 1 };
        self.game = Some(opening);
        self.game_outpoint = Some(TransactionOutpoint { transaction_id: executed_txid, index: 2 });
        self.push_message(
            &white.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: white.name.clone(),
                kind: OffchainMessageKind::GameStarted { white: white.name.clone(), black: black.name.clone() },
            },
        );
        self.push_message(
            &black.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: black.name.clone(),
                kind: OffchainMessageKind::GameStarted { white: white.name.clone(), black: black.name.clone() },
            },
        );
        self.history.push(submission);
        Ok(())
    }

    pub fn submit_move(&mut self, actor: &SigningPlayer, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.submit_move_internal(actor, mv, CLEAR, false)
    }

    pub fn offer_draw(&mut self, actor: &SigningPlayer, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.submit_move_internal(actor, mv, OFFER, false)
    }

    pub fn force_move(&mut self, actor: &SigningPlayer, mv: MoveSpec) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.submit_move_internal(actor, mv, CLEAR, true)
    }

    fn build_mux_route(
        &self,
        builder: &TxBuilder<'_>,
        request: MuxRouteRequest<'_>,
    ) -> Result<(Transaction, CovenantOutput), OrchestratorError> {
        let game_outpoint = self.game_outpoint.ok_or_else(|| OrchestratorError("missing game outpoint".to_string()))?;
        let game_utxo = builder
            .covenant_utxo("Mux", game_source_state(request.game), 1_000, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build active Mux UTXO"))?;
        let selected_target = request.target.to_string();
        let keypair = request.actor.keypair;
        let public_key = request.actor.pubkey_bytes.clone();
        let player_id = request.actor.player_id.ok_or_else(|| OrchestratorError("missing player id".to_string()))?;
        let mv = request.mv;
        let termination_action = request.termination_action;
        let route_context = TxContext::new()
            .actor_input(
                "Mux",
                game_source_state(request.game),
                EntryCall::new("route").args_with(move |tx, input_index| {
                    args![
                        actor_arg(selected_target.clone()),
                        mv.from_x,
                        mv.from_y,
                        mv.to_x,
                        mv.to_y,
                        state_byte(mv.promo_piece),
                        state_byte(termination_action),
                        sign_builder_input(tx, input_index, &keypair),
                        public_key.clone(),
                        player_id,
                    ]
                }),
                game_outpoint,
                game_utxo,
                0,
            )
            .actor_output(request.target, game_source_state(request.pending), CovenantBinding::new(0, self.covenant_id), 1_000);
        let tx = builder.build(&route_context).map_err(orchestrator_builder_error("route Mux to move actor"))?;
        let output = CovenantOutput::from_tx(&tx, 0).map_err(orchestrator_builder_error("read routed move output"))?;
        Ok((tx, output))
    }

    fn submit_move_internal(
        &mut self,
        actor: &SigningPlayer,
        mv: MoveSpec,
        termination_action: i64,
        allow_partial_commit: bool,
    ) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
        let actor_side = player_side(actor, &game)?;
        if actor_side != side_from_turn(game.turn) {
            return Err(OrchestratorError(format!("it is not {}'s turn", actor.name)));
        }

        let worker = determine_worker(&game.board, mv)?;
        let pending = pending_state_for_move(&game, mv, termination_action);
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let (executed_route_tx, worker_output) = self.build_mux_route(
            &builder,
            MuxRouteRequest { actor, game: &game, target: worker_actor(worker), pending: &pending, mv, termination_action },
        )?;
        let worker_outpoint = worker_output.outpoint;
        let next = apply_worker_state(worker, &pending, mv, allow_partial_commit)?;
        let apply_context = TxContext::new()
            .actor_input(worker_actor(worker), game_source_state(&pending), "apply", worker_output.outpoint, worker_output.utxo, 0)
            .actor_output("Mux", game_source_state(&next), CovenantBinding::new(0, self.covenant_id), 1_000);
        let apply_result = builder.build(&apply_context);
        let executed_apply_tx = match apply_result {
            Ok(tx) => tx,
            Err(err) => {
                if !allow_partial_commit {
                    return Err(OrchestratorError(format!("apply failed: {err}")));
                }
                let route_submission = submitted_tx("route", &executed_route_tx, vec![actor.name.clone()]);
                return self.commit_partial_worker(
                    actor,
                    PartialWorkerCommit {
                        worker,
                        state: pending,
                        outpoint: worker_outpoint,
                        mv,
                        transactions: vec![executed_route_tx],
                        submissions: vec![route_submission],
                    },
                );
            }
        };

        let route_submission = submitted_tx("route", &executed_route_tx, vec![actor.name.clone()]);
        let apply_submission = submitted_tx("worker_apply", &executed_apply_tx, vec![]);
        self.transactions.push(executed_route_tx);
        self.transactions.push(executed_apply_tx);

        let move_label = mv.label();
        let recipient = if actor_side == Side::White {
            self.players
                .iter()
                .find_map(|(name, state)| {
                    (player_ref_hash(state.owner_hash, state.player_id) == game.black_player).then_some(name.clone())
                })
                .ok_or_else(|| OrchestratorError("missing black owner".to_string()))?
        } else {
            self.players
                .iter()
                .find_map(|(name, state)| {
                    (player_ref_hash(state.owner_hash, state.player_id) == game.white_player).then_some(name.clone())
                })
                .ok_or_else(|| OrchestratorError("missing white owner".to_string()))?
        };
        self.push_message(
            &recipient,
            OffchainMessage {
                from: actor.name.clone(),
                to: recipient.clone(),
                kind: OffchainMessageKind::MoveNotice { actor: actor.name.clone(), worker, move_label: move_label.clone(), mv },
            },
        );
        if termination_action == OFFER {
            self.push_message(
                &recipient,
                OffchainMessage {
                    from: actor.name.clone(),
                    to: recipient.clone(),
                    kind: OffchainMessageKind::DrawOffered { actor: actor.name.clone() },
                },
            );
        }
        self.game = Some(next);
        self.game_outpoint =
            Some(TransactionOutpoint { transaction_id: self.transactions.last().expect("apply tx exists").id(), index: 0 });

        let submissions = vec![route_submission, apply_submission];
        self.history.extend(submissions.clone());
        Ok(submissions)
    }

    pub fn challenge_castle(
        &mut self,
        actor: &SigningPlayer,
        mv: MoveSpec,
        allow_partial_commit: bool,
    ) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
        let actor_side = player_side(actor, &game)?;
        if actor_side != side_from_turn(game.turn) {
            return Err(OrchestratorError(format!("it is not {}'s turn", actor.name)));
        }
        if game.recent_castle == CLEAR {
            return Err(OrchestratorError("the previous move was not a castle".to_string()));
        }

        let mut prep = pending_state_for_move(&game, mv, CLEAR);
        prep.recent_castle = game.recent_castle;
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let (route_tx, prep_output) = self.build_mux_route(
            &builder,
            MuxRouteRequest { actor, game: &game, target: "CastleChallengePrep", pending: &prep, mv, termination_action: CLEAR },
        )?;
        let prep_outpoint = prep_output.outpoint;
        let route_submission = submitted_tx("castle_challenge_route", &route_tx, vec![actor.name.clone()]);

        let proof = match castle_challenge_proof_state(&prep) {
            Ok(proof) => proof,
            Err(_) if allow_partial_commit => {
                return self.commit_partial_worker(
                    actor,
                    PartialWorkerCommit {
                        worker: WorkerKind::CastleChallenge,
                        state: prep,
                        outpoint: prep_outpoint,
                        mv,
                        transactions: vec![route_tx],
                        submissions: vec![route_submission],
                    },
                );
            }
            Err(err) => return Err(err),
        };
        let worker = match determine_challenge_worker(&proof.board, mv) {
            Ok(worker) => worker,
            Err(_) if allow_partial_commit => {
                return self.commit_partial_worker(
                    actor,
                    PartialWorkerCommit {
                        worker: WorkerKind::CastleChallenge,
                        state: prep,
                        outpoint: prep_outpoint,
                        mv,
                        transactions: vec![route_tx],
                        submissions: vec![route_submission],
                    },
                );
            }
            Err(err) => return Err(err),
        };
        let selected_worker = worker_actor(worker).to_string();
        let prep_context = TxContext::new()
            .actor_input(
                "CastleChallengePrep",
                game_source_state(&prep),
                EntryCall::new("apply").args(args![actor_arg(selected_worker)]),
                prep_output.outpoint,
                prep_output.utxo,
                0,
            )
            .actor_output(worker_actor(worker), game_source_state(&proof), CovenantBinding::new(0, self.covenant_id), 1_000);
        let prep_tx = match builder.build(&prep_context) {
            Ok(tx) => tx,
            Err(_) if allow_partial_commit => {
                return self.commit_partial_worker(
                    actor,
                    PartialWorkerCommit {
                        worker: WorkerKind::CastleChallenge,
                        state: prep,
                        outpoint: prep_outpoint,
                        mv,
                        transactions: vec![route_tx],
                        submissions: vec![route_submission],
                    },
                );
            }
            Err(err) => return Err(OrchestratorError(format!("castle challenge preparation failed: {err}"))),
        };
        let worker_output =
            CovenantOutput::from_tx(&prep_tx, 0).map_err(orchestrator_builder_error("read prepared challenge worker output"))?;
        let worker_outpoint = worker_output.outpoint;
        let prep_submission = submitted_tx("castle_challenge_prepare", &prep_tx, vec![]);

        let next = match apply_worker_state(worker, &proof, mv, true) {
            Ok(next) => next,
            Err(_) if allow_partial_commit => {
                return self.commit_partial_worker(
                    actor,
                    PartialWorkerCommit {
                        worker,
                        state: proof,
                        outpoint: worker_outpoint,
                        mv,
                        transactions: vec![route_tx, prep_tx],
                        submissions: vec![route_submission, prep_submission],
                    },
                );
            }
            Err(err) => return Err(err),
        };
        let apply_context = TxContext::new()
            .actor_input(worker_actor(worker), game_source_state(&proof), "apply", worker_output.outpoint, worker_output.utxo, 0)
            .actor_output("Mux", game_source_state(&next), CovenantBinding::new(0, self.covenant_id), 1_000);
        let apply_tx = match builder.build(&apply_context) {
            Ok(tx) => tx,
            Err(_) if allow_partial_commit => {
                return self.commit_partial_worker(
                    actor,
                    PartialWorkerCommit {
                        worker,
                        state: proof,
                        outpoint: worker_outpoint,
                        mv,
                        transactions: vec![route_tx, prep_tx],
                        submissions: vec![route_submission, prep_submission],
                    },
                );
            }
            Err(err) => return Err(OrchestratorError(format!("castle challenge apply failed: {err}"))),
        };

        let apply_txid = apply_tx.id();
        let apply_submission = submitted_tx("castle_challenge_apply", &apply_tx, vec![]);
        self.transactions.extend([route_tx, prep_tx, apply_tx]);
        self.game = Some(next);
        self.game_outpoint = Some(TransactionOutpoint::new(apply_txid, 0));
        let recipient = self.owner_name(if actor_side == Side::White { game.black_player } else { game.white_player })?;
        self.push_message(
            &recipient,
            OffchainMessage {
                from: actor.name.clone(),
                to: recipient.clone(),
                kind: OffchainMessageKind::MoveNotice { actor: actor.name.clone(), worker, move_label: mv.label(), mv },
            },
        );
        let submissions = vec![route_submission, prep_submission, apply_submission];
        self.history.extend(submissions.clone());
        Ok(submissions)
    }

    fn commit_partial_worker(
        &mut self,
        actor: &SigningPlayer,
        partial: PartialWorkerCommit,
    ) -> Result<Vec<SubmittedTx>, OrchestratorError> {
        self.transactions.extend(partial.transactions);
        self.game = None;
        self.game_outpoint = None;
        self.active_worker =
            Some(ActiveWorkerState { kind: partial.worker, state: partial.state.clone(), outpoint: partial.outpoint });
        self.notify_timeout_available(actor, &partial.state, partial.worker, partial.mv)?;
        self.history.extend(partial.submissions.clone());
        Ok(partial.submissions)
    }

    fn notify_timeout_available(
        &mut self,
        actor: &SigningPlayer,
        state: &GameStateData,
        worker: WorkerKind,
        mv: MoveSpec,
    ) -> Result<(), OrchestratorError> {
        let status = timeout_status(state.turn, state.draw_state);
        let result = result_from_status(status)?;
        let recipient_refs = if status == DRAW {
            vec![state.white_player, state.black_player]
        } else if status == WWIN {
            vec![state.white_player]
        } else {
            vec![state.black_player]
        };
        for recipient_ref in recipient_refs {
            let recipient = self.owner_name(recipient_ref)?;
            self.push_message(
                &recipient,
                OffchainMessage {
                    from: actor.name.clone(),
                    to: recipient.clone(),
                    kind: OffchainMessageKind::TimeoutClaimAvailable { result, worker, move_label: mv.label() },
                },
            );
        }
        Ok(())
    }

    fn claim_worker_timeout(&mut self, claimer: &SigningPlayer, active_worker: ActiveWorkerState) -> Result<(), OrchestratorError> {
        player_side(claimer, &active_worker.state)?;
        let status = timeout_status(active_worker.state.turn, active_worker.state.draw_state);
        let result = result_from_status(status)?;
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let worker_utxo = builder
            .covenant_utxo(
                worker_actor(active_worker.kind),
                game_source_state(&active_worker.state),
                1_000,
                0,
                false,
                Some(self.covenant_id),
            )
            .map_err(orchestrator_builder_error("build timed-out worker UTXO"))?;
        let context = TxContext::new()
            .actor_input(
                worker_actor(active_worker.kind),
                game_source_state(&active_worker.state),
                "timeout",
                active_worker.outpoint,
                worker_utxo,
                timeout_sequence(active_worker.state.move_timeout)?,
            )
            .actor_output(
                "Settle",
                settle_source_state(active_worker.state.white_player, active_worker.state.black_player, status),
                CovenantBinding::new(0, self.covenant_id),
                1_000,
            );
        let executed_tx = builder.build(&context).map_err(orchestrator_builder_error("claim worker timeout"))?;
        let submission = submitted_tx("worker_timeout", &executed_tx, vec![]);
        self.transactions.push(executed_tx.clone());
        self.active_worker = None;
        self.active_settle = Some(ActiveSettleState {
            white_player: active_worker.state.white_player,
            black_player: active_worker.state.black_player,
            status,
            outpoint: TransactionOutpoint { transaction_id: executed_tx.id(), index: 0 },
        });
        self.notify_settlement(active_worker.state.white_player, active_worker.state.black_player, result)?;
        self.history.push(submission);
        Ok(())
    }

    fn claim_mux_timeout(&mut self, claimer: &SigningPlayer, game: GameStateData) -> Result<(), OrchestratorError> {
        let claimer_side = player_side(claimer, &game)?;
        if claimer_side == side_from_turn(game.turn) {
            return Err(OrchestratorError(format!("{} is not entitled to claim this timeout", claimer.name)));
        }

        let status = timeout_status(game.turn, game.draw_state);
        let result = result_from_status(status)?;
        let game_outpoint = self.game_outpoint.ok_or_else(|| OrchestratorError("missing game outpoint".to_string()))?;
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let game_utxo = builder
            .covenant_utxo("Mux", game_source_state(&game), 1_000, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build timed-out Mux UTXO"))?;
        let keypair = claimer.keypair;
        let public_key = claimer.pubkey_bytes.clone();
        let player_id = claimer.player_id.ok_or_else(|| OrchestratorError("missing player id".to_string()))?;
        let context = TxContext::new()
            .actor_input(
                "Mux",
                game_source_state(&game),
                EntryCall::new("timeout").args_with(move |tx, input_index| {
                    args![sign_builder_input(tx, input_index, &keypair), public_key.clone(), player_id]
                }),
                game_outpoint,
                game_utxo,
                timeout_sequence(game.move_timeout)?,
            )
            .actor_output(
                "Settle",
                settle_source_state(game.white_player, game.black_player, status),
                CovenantBinding::new(0, self.covenant_id),
                1_000,
            );
        let executed_tx = builder.build(&context).map_err(orchestrator_builder_error("claim Mux timeout"))?;
        let executed_txid = executed_tx.id();
        let submission = submitted_tx("mux_timeout", &executed_tx, vec![claimer.name.clone()]);
        self.transactions.push(executed_tx);
        self.game = None;
        self.game_outpoint = None;
        self.active_settle = Some(ActiveSettleState {
            white_player: game.white_player,
            black_player: game.black_player,
            status,
            outpoint: TransactionOutpoint::new(executed_txid, 0),
        });
        self.notify_settlement(game.white_player, game.black_player, result)?;
        self.history.push(submission);
        Ok(())
    }

    pub fn claim_timeout(&mut self, claimer: &SigningPlayer) -> Result<(), OrchestratorError> {
        if let Some(active_worker) = self.active_worker.clone() {
            self.claim_worker_timeout(claimer, active_worker)
        } else if let Some(game) = self.game.clone() {
            self.claim_mux_timeout(claimer, game)
        } else {
            Err(OrchestratorError("missing active game or worker".to_string()))
        }
    }

    pub fn claim_draw(&mut self, actor: &SigningPlayer) -> Result<(), OrchestratorError> {
        self.terminate_game(actor, CLAIM, "draw_claim")
    }

    pub fn accept_draw(&mut self, actor: &SigningPlayer) -> Result<(), OrchestratorError> {
        self.terminate_game(actor, ACCEPT, "draw_accept")
    }

    pub fn surrender(&mut self, actor: &SigningPlayer) -> Result<(), OrchestratorError> {
        self.terminate_game(actor, SURRENDER, "surrender")
    }

    fn terminate_game(
        &mut self,
        actor: &SigningPlayer,
        termination_action: i64,
        action: &'static str,
    ) -> Result<(), OrchestratorError> {
        let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
        let actor_side = player_side(actor, &game)?;
        if actor_side != side_from_turn(game.turn) {
            return Err(OrchestratorError(format!("it is not {}'s turn", actor.name)));
        }

        let (next_turn, next_status, next_draw_state) = match termination_action {
            CLAIM => {
                if game.draw_state != NORMAL || game.recent_castle != CLEAR {
                    return Err(OrchestratorError("a draw claim requires a normal Mux state without a pending castle".to_string()));
                }
                (1 - game.turn, game.status, CLAIMED)
            }
            SURRENDER => (game.turn, if game.turn == WHITE { BWIN } else { WWIN }, NORMAL),
            ACCEPT => {
                if game.draw_state + game.turn != BOFFER {
                    return Err(OrchestratorError("no draw offer is available to accept".to_string()));
                }
                (game.turn, DRAW, NORMAL)
            }
            _ => return Err(OrchestratorError(format!("unsupported termination action {termination_action}"))),
        };
        let next = GameStateData {
            white_player: game.white_player,
            black_player: game.black_player,
            board: game.board.clone(),
            turn: next_turn,
            status: next_status,
            move_timeout: game.move_timeout,
            castle_rights: game.castle_rights,
            en_passant_idx: OFFBOARD,
            pending_src_idx: OFFBOARD,
            pending_dst_idx: OFFBOARD,
            pending_promo: 0,
            recent_castle: 0,
            draw_state: next_draw_state,
            move_log: game.move_log.clone(),
        };
        let game_outpoint = self.game_outpoint.ok_or_else(|| OrchestratorError("missing game outpoint".to_string()))?;
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let game_utxo = builder
            .covenant_utxo("Mux", game_source_state(&game), 1_000, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build active Mux UTXO"))?;
        let keypair = actor.keypair;
        let public_key = actor.pubkey_bytes.clone();
        let player_id = actor.player_id.ok_or_else(|| OrchestratorError("missing player id".to_string()))?;
        let context = TxContext::new()
            .actor_input(
                "Mux",
                game_source_state(&game),
                EntryCall::new("terminate").args_with(move |tx, input_index| {
                    args![state_byte(termination_action), sign_builder_input(tx, input_index, &keypair), public_key.clone(), player_id]
                }),
                game_outpoint,
                game_utxo,
                0,
            )
            .actor_output("Mux", game_source_state(&next), CovenantBinding::new(0, self.covenant_id), 1_000);
        let executed_tx = builder.build(&context).map_err(orchestrator_builder_error("terminate game"))?;
        let submission = submitted_tx(action, &executed_tx, vec![actor.name.clone()]);
        self.transactions.push(executed_tx);
        self.game = Some(next);
        self.game_outpoint =
            Some(TransactionOutpoint { transaction_id: self.transactions.last().expect("termination tx exists").id(), index: 0 });
        let recipient = self.owner_name(if actor_side == Side::White { game.black_player } else { game.white_player })?;
        let kind = match termination_action {
            CLAIM => Some(OffchainMessageKind::DrawClaimed { actor: actor.name.clone() }),
            ACCEPT => Some(OffchainMessageKind::DrawAccepted { actor: actor.name.clone() }),
            _ => None,
        };
        if let Some(kind) = kind {
            self.push_message(&recipient, OffchainMessage { from: actor.name.clone(), to: recipient.clone(), kind });
        }
        self.history.push(submission);
        Ok(())
    }

    pub fn request_settlement(
        &mut self,
        requester: &SigningPlayer,
        opponent: &SigningPlayer,
        result: GameResult,
    ) -> Result<(), OrchestratorError> {
        self.require_registered(requester)?;
        self.require_registered(opponent)?;
        let game = self.game.as_ref().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
        let requester_ref =
            requester.player_ref.as_ref().ok_or_else(|| OrchestratorError("requester missing player ref".to_string()))?;
        let opponent_ref = opponent.player_ref.as_ref().ok_or_else(|| OrchestratorError("opponent missing player ref".to_string()))?;
        let white_name = if requester_ref == &game.white_player {
            requester.name.clone()
        } else if opponent_ref == &game.white_player {
            opponent.name.clone()
        } else {
            return Err(OrchestratorError("missing white player in settlement request".to_string()));
        };
        let black_name = if requester_ref == &game.black_player {
            requester.name.clone()
        } else if opponent_ref == &game.black_player {
            opponent.name.clone()
        } else {
            return Err(OrchestratorError("missing black player in settlement request".to_string()));
        };
        for recipient in [white_name, black_name] {
            self.push_message(
                &recipient,
                OffchainMessage {
                    from: requester.name.clone(),
                    to: recipient.clone(),
                    kind: OffchainMessageKind::SettlementRequest { result },
                },
            );
        }
        Ok(())
    }

    pub fn settle_game(&mut self, white: &SigningPlayer, black: &SigningPlayer, result: GameResult) -> Result<(), OrchestratorError> {
        let expected_status = status_from_result(result);
        let white_state = self.players.get(&white.name).cloned().ok_or_else(|| OrchestratorError("missing white".to_string()))?;
        let black_state = self.players.get(&black.name).cloned().ok_or_else(|| OrchestratorError("missing black".to_string()))?;

        let white_ref = white.player_ref.ok_or_else(|| OrchestratorError("white missing player ref".to_string()))?;
        let black_ref = black.player_ref.ok_or_else(|| OrchestratorError("black missing player ref".to_string()))?;
        let (settlement, mux_settle_tx) = if let Some(active_settle) = self.active_settle.clone() {
            if active_settle.status != expected_status {
                return Err(OrchestratorError(format!(
                    "active settle status {} does not match requested result {}",
                    active_settle.status, expected_status
                )));
            }
            if active_settle.white_player != white_ref || active_settle.black_player != black_ref {
                return Err(OrchestratorError("active settle does not match provided players".to_string()));
            }
            let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
            let utxo = builder
                .covenant_utxo(
                    "Settle",
                    settle_source_state(white_ref, black_ref, expected_status),
                    1_000,
                    0,
                    false,
                    Some(self.covenant_id),
                )
                .map_err(orchestrator_builder_error("build active Settle UTXO"))?;
            (CovenantOutput { index: 0, covenant_id: self.covenant_id, outpoint: active_settle.outpoint, utxo }, None)
        } else {
            let game = self.game.clone().ok_or_else(|| OrchestratorError("missing game".to_string()))?;
            if game.status != expected_status {
                return Err(OrchestratorError(format!(
                    "terminal game status {} does not match requested result {}",
                    game.status, expected_status
                )));
            }
            let game_outpoint = self.game_outpoint.ok_or_else(|| OrchestratorError("missing game outpoint".to_string()))?;
            let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
            let game_utxo = builder
                .covenant_utxo("Mux", game_source_state(&game), 1_000, 0, false, Some(self.covenant_id))
                .map_err(orchestrator_builder_error("build terminal Mux UTXO"))?;
            let context =
                TxContext::new().actor_input("Mux", game_source_state(&game), "settle", game_outpoint, game_utxo, 0).actor_output(
                    "Settle",
                    settle_source_state(white_ref, black_ref, expected_status),
                    CovenantBinding::new(0, self.covenant_id),
                    1_000,
                );
            let tx = builder.build(&context).map_err(orchestrator_builder_error("route terminal game to settlement"))?;
            let settlement = CovenantOutput::from_tx(&tx, 0).map_err(orchestrator_builder_error("read Settle output"))?;
            (settlement, Some(tx))
        };
        let mux_submission = mux_settle_tx.as_ref().map(|tx| submitted_tx("mux_settle", tx, vec![]));
        if let Some(tx) = mux_settle_tx.as_ref() {
            self.transactions.push(tx.clone());
        }

        let mut next_white = white_state.clone();
        let mut next_black = black_state.clone();
        if next_white.open_games <= 0 || next_black.open_games <= 0 {
            return Err(OrchestratorError("cannot settle players without open games".to_string()));
        }
        next_white.open_games -= 1;
        next_black.open_games -= 1;
        next_white.games += 1;
        next_black.games += 1;

        let (white_actual, black_actual) = match result {
            GameResult::WhiteWin => {
                next_white.wins += 1;
                next_black.losses += 1;
                (1000, 0)
            }
            GameResult::BlackWin => {
                next_white.losses += 1;
                next_black.wins += 1;
                (0, 1000)
            }
            GameResult::Draw => {
                next_white.draws += 1;
                next_black.draws += 1;
                (500, 500)
            }
        };

        let white_old_rating = next_white.rating;
        let black_old_rating = next_black.rating;
        next_white.rating = approx_updated_rating(white_old_rating, black_old_rating, white_actual);
        next_black.rating = approx_updated_rating(black_old_rating, white_old_rating, black_actual);

        let stake = settlement.utxo.amount;
        match result {
            GameResult::WhiteWin => {
                next_white.value += stake;
            }
            GameResult::BlackWin => {
                next_black.value += stake;
            }
            GameResult::Draw => {
                let white_share = stake / 2;
                let black_share = stake - white_share;
                next_white.value += white_share;
                next_black.value += black_share;
            }
        }

        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let white_utxo = builder
            .covenant_utxo("Player", player_source_state(&white_state), white_state.value, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build white settlement Player UTXO"))?;
        let black_utxo = builder
            .covenant_utxo("Player", player_source_state(&black_state), black_state.value, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build black settlement Player UTXO"))?;
        let context = TxContext::new()
            .actor_input(
                "Settle",
                settle_source_state(white_ref, black_ref, expected_status),
                "settle",
                settlement.outpoint,
                settlement.utxo,
                0,
            )
            .actor_input("Player", player_source_state(&white_state), "delegate_settle", white_state.outpoint, white_utxo, 0)
            .actor_input("Player", player_source_state(&black_state), "delegate_settle", black_state.outpoint, black_utxo, 0)
            .actor_output("Player", player_source_state(&next_white), CovenantBinding::new(0, self.covenant_id), next_white.value)
            .actor_output("Player", player_source_state(&next_black), CovenantBinding::new(0, self.covenant_id), next_black.value);
        let executed_tx = builder.build(&context).map_err(orchestrator_builder_error("settle game into players"))?;
        let executed_txid = executed_tx.id();
        let settlement_submission = submitted_tx("settle", &executed_tx, vec![]);
        self.transactions.push(executed_tx);

        self.players.insert(white.name.clone(), next_white);
        self.players.insert(black.name.clone(), next_black);
        self.players.get_mut(&white.name).expect("white tracked").outpoint =
            TransactionOutpoint { transaction_id: executed_txid, index: 0 };
        self.players.get_mut(&black.name).expect("black tracked").outpoint =
            TransactionOutpoint { transaction_id: executed_txid, index: 1 };
        self.game = None;
        self.game_outpoint = None;
        self.active_worker = None;
        self.active_settle = None;
        self.push_message(
            &white.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: white.name.clone(),
                kind: OffchainMessageKind::SettlementNotice { result },
            },
        );
        self.push_message(
            &black.name,
            OffchainMessage {
                from: "arena".to_string(),
                to: black.name.clone(),
                kind: OffchainMessageKind::SettlementNotice { result },
            },
        );
        if let Some(submission) = mux_submission {
            self.history.push(submission);
        }
        self.history.push(settlement_submission);
        Ok(())
    }

    pub fn retire_player(&mut self, player: &SigningPlayer) -> Result<(), OrchestratorError> {
        let state = self.players.get(&player.name).cloned().ok_or_else(|| OrchestratorError("missing player".to_string()))?;
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let player_utxo = builder
            .covenant_utxo("Player", player_source_state(&state), state.value, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build retiring Player UTXO"))?;
        let keypair = player.keypair;
        let public_key = player.pubkey_bytes.clone();
        let context = TxContext::new().actor_input(
            "Player",
            player_source_state(&state),
            EntryCall::new("retire")
                .args_with(move |tx, input_index| args![sign_builder_input(tx, input_index, &keypair), public_key.clone()]),
            state.outpoint,
            player_utxo,
            0,
        );
        let executed_tx = builder.build(&context).map_err(orchestrator_builder_error("retire player"))?;
        let submission = submitted_tx("retire", &executed_tx, vec![player.name.clone()]);
        self.transactions.push(executed_tx);
        self.players.remove(&player.name);
        self.history.push(submission);
        Ok(())
    }

    pub fn rebalance_player(&mut self, player: &SigningPlayer, value: u64) -> Result<(), OrchestratorError> {
        let state = self.players.get(&player.name).cloned().ok_or_else(|| OrchestratorError("missing player".to_string()))?;
        let builder = TxBuilder::new(&self.artifact).map_err(orchestrator_builder_error("initialize Argent builder"))?;
        let player_utxo = builder
            .covenant_utxo("Player", player_source_state(&state), state.value, 0, false, Some(self.covenant_id))
            .map_err(orchestrator_builder_error("build rebalancing Player UTXO"))?;
        let keypair = player.keypair;
        let public_key = player.pubkey_bytes.clone();
        let context = TxContext::new()
            .actor_input(
                "Player",
                player_source_state(&state),
                EntryCall::new("rebalance")
                    .args_with(move |tx, input_index| args![sign_builder_input(tx, input_index, &keypair), public_key.clone()]),
                state.outpoint,
                player_utxo,
                0,
            )
            .actor_output("Player", player_source_state(&state), CovenantBinding::new(0, self.covenant_id), value);
        let tx = builder.build(&context).map_err(orchestrator_builder_error("rebalance Player"))?;
        let txid = tx.id();
        let submission = submitted_tx("player_rebalance", &tx, vec![player.name.clone()]);
        self.transactions.push(tx);
        *self.players.get_mut(&player.name).expect("rebalanced player remains tracked") =
            PlayerStateData { outpoint: TransactionOutpoint::new(txid, 0), value, ..state };
        self.history.push(submission);
        Ok(())
    }

    fn push_message(&mut self, recipient: &str, message: OffchainMessage) {
        self.messages.entry(recipient.to_string()).or_default().push(message);
    }

    fn require_registered(&self, player: &SigningPlayer) -> Result<(), OrchestratorError> {
        if player.player_ref.is_none() || player.player_id.is_none() {
            return Err(OrchestratorError(format!("{} is not registered", player.name)));
        }
        Ok(())
    }

    fn notify_settlement(&mut self, white_player: Hash, black_player: Hash, result: GameResult) -> Result<(), OrchestratorError> {
        for recipient in [self.owner_name(white_player)?, self.owner_name(black_player)?] {
            self.push_message(
                &recipient,
                OffchainMessage {
                    from: "arena".to_string(),
                    to: recipient.clone(),
                    kind: OffchainMessageKind::SettlementRequest { result },
                },
            );
        }
        Ok(())
    }

    fn player_account(&self, player_ref: Hash) -> Result<PlayerAccount, OrchestratorError> {
        self.players
            .iter()
            .find_map(|(name, state)| {
                (player_ref_hash(state.owner_hash, state.player_id) == player_ref).then_some(PlayerAccount {
                    owner_name: name.clone(),
                    owner_hash: state.owner_hash,
                    player_id: state.player_id,
                    player_ref,
                    value: state.value,
                    open_games: state.open_games,
                    rating: state.rating,
                    games: state.games,
                    wins: state.wins,
                    draws: state.draws,
                    losses: state.losses,
                })
            })
            .ok_or_else(|| OrchestratorError("missing player account".to_string()))
    }
}

fn square_idx(x: i64, y: i64) -> i64 {
    y * 8 + x
}

fn worker_actor(worker: WorkerKind) -> &'static str {
    match worker {
        WorkerKind::Pawn => "Pawn",
        WorkerKind::Knight => "Knight",
        WorkerKind::Vert => "Vert",
        WorkerKind::Horiz => "Horiz",
        WorkerKind::Diag => "Diag",
        WorkerKind::King => "King",
        WorkerKind::Castle => "Castle",
        WorkerKind::CastleChallenge => "CastleChallengePrep",
    }
}

fn side_from_turn(turn: i64) -> Side {
    if turn == 0 {
        Side::White
    } else {
        Side::Black
    }
}

fn status_from_result(result: GameResult) -> i64 {
    match result {
        GameResult::WhiteWin => 1,
        GameResult::BlackWin => 2,
        GameResult::Draw => 3,
    }
}

fn result_from_status(status: i64) -> Result<GameResult, OrchestratorError> {
    match status {
        WWIN => Ok(GameResult::WhiteWin),
        BWIN => Ok(GameResult::BlackWin),
        DRAW => Ok(GameResult::Draw),
        _ => Err(OrchestratorError(format!("status {status} is not terminal"))),
    }
}

fn timeout_status(turn: i64, draw_state: i64) -> i64 {
    if draw_state == CLAIMED {
        DRAW
    } else if turn == WHITE {
        BWIN
    } else {
        WWIN
    }
}

fn timeout_sequence(move_timeout: i64) -> Result<u64, OrchestratorError> {
    u64::try_from(move_timeout).map_err(|_| OrchestratorError("move timeout cannot be negative".to_string()))
}

fn player_side(player: &SigningPlayer, game: &GameStateData) -> Result<Side, OrchestratorError> {
    let player_ref = player.player_ref.ok_or_else(|| OrchestratorError(format!("{} missing player ref", player.name)))?;
    if player_ref == game.white_player {
        Ok(Side::White)
    } else if player_ref == game.black_player {
        Ok(Side::Black)
    } else {
        Err(OrchestratorError(format!("{} is not part of the active game", player.name)))
    }
}

fn determine_worker(board: &[u8], mv: MoveSpec) -> Result<WorkerKind, OrchestratorError> {
    if !(0..8).contains(&mv.from_x) || !(0..8).contains(&mv.from_y) || !(0..8).contains(&mv.to_x) || !(0..8).contains(&mv.to_y) {
        return Err(OrchestratorError("move coordinates must stay on board".to_string()));
    }
    let piece = board[square_idx(mv.from_x, mv.from_y) as usize];
    if piece == 0 {
        return Err(OrchestratorError("no piece on source square".to_string()));
    }
    let base = if piece > 8 { piece - 8 } else { piece };
    let dx = mv.to_x - mv.from_x;
    let dy = mv.to_y - mv.from_y;
    match base {
        1 => Ok(WorkerKind::Pawn),
        2 => Ok(WorkerKind::Knight),
        3 => Ok(WorkerKind::Diag),
        4 => {
            if dx == 0 {
                Ok(WorkerKind::Vert)
            } else if dy == 0 {
                Ok(WorkerKind::Horiz)
            } else {
                Err(OrchestratorError("rook move must stay on file or rank".to_string()))
            }
        }
        5 => {
            if dx == 0 {
                Ok(WorkerKind::Vert)
            } else if dy == 0 {
                Ok(WorkerKind::Horiz)
            } else if dx.abs() == dy.abs() {
                Ok(WorkerKind::Diag)
            } else {
                Err(OrchestratorError("queen move must be straight or diagonal".to_string()))
            }
        }
        6 => {
            if dy == 0 && dx.abs() == 2 {
                Ok(WorkerKind::Castle)
            } else {
                Ok(WorkerKind::King)
            }
        }
        _ => Err(OrchestratorError("unknown piece kind".to_string())),
    }
}

fn determine_challenge_worker(board: &[u8], mv: MoveSpec) -> Result<WorkerKind, OrchestratorError> {
    match determine_worker(board, mv)? {
        WorkerKind::Castle => Ok(WorkerKind::King),
        worker => Ok(worker),
    }
}

fn castle_challenge_proof_state(game: &GameStateData) -> Result<GameStateData, OrchestratorError> {
    if game.board.len() != 64 {
        return Err(OrchestratorError(format!("board must contain exactly 64 squares, got {}", game.board.len())));
    }
    if game.draw_state != NORMAL {
        return Err(OrchestratorError("a castle challenge requires the normal draw state".to_string()));
    }
    if !(1..=4).contains(&game.recent_castle) {
        return Err(OrchestratorError("castle challenge marker must be between 1 and 4".to_string()));
    }
    if game.pending_src_idx == game.pending_dst_idx {
        return Err(OrchestratorError("castle challenge source and destination must differ".to_string()));
    }

    let is_white_castle = game.recent_castle == 1 || game.recent_castle == 2;
    let is_king_side = game.recent_castle == 1 || game.recent_castle == 3;
    let row_base = if is_white_castle { 0 } else { 56 };
    let king_piece = if is_white_castle { 0x06 } else { 0x0e };
    let rook_piece = if is_white_castle { 0x04 } else { 0x0c };
    let start_idx = row_base + 4;
    let transit_idx = if is_king_side { row_base + 5 } else { row_base + 3 };
    let destination_idx = if is_king_side { row_base + 6 } else { row_base + 2 };
    let phase = if game.pending_dst_idx == start_idx {
        1
    } else if game.pending_dst_idx == transit_idx {
        2
    } else if game.pending_dst_idx == destination_idx {
        3
    } else {
        return Err(OrchestratorError("castle challenge destination is not on the castle lane".to_string()));
    };

    let mut proof_board = game.board.clone();
    if is_king_side {
        let (a, b, c, d) = match phase {
            1 => (king_piece, 0, 0, rook_piece),
            2 => (0, king_piece, 0, rook_piece),
            _ => (0, rook_piece, king_piece, 0),
        };
        proof_board[(row_base + 4) as usize] = a;
        proof_board[(row_base + 5) as usize] = b;
        proof_board[(row_base + 6) as usize] = c;
        proof_board[(row_base + 7) as usize] = d;
    } else {
        let (a, b, c, d) = match phase {
            1 => (rook_piece, 0, 0, king_piece),
            2 => (rook_piece, 0, king_piece, 0),
            _ => (0, king_piece, rook_piece, 0),
        };
        proof_board[row_base as usize] = a;
        proof_board[(row_base + 2) as usize] = b;
        proof_board[(row_base + 3) as usize] = c;
        proof_board[(row_base + 4) as usize] = d;
    }

    Ok(GameStateData { board: proof_board, en_passant_idx: OFFBOARD, pending_promo: CLEAR, ..game.clone() })
}

fn pending_state_for_move(game: &GameStateData, mv: MoveSpec, termination_action: i64) -> GameStateData {
    let mut draw_state = game.draw_state;
    if draw_state > NORMAL {
        draw_state = NORMAL;
    }
    if termination_action == OFFER {
        draw_state = WOFFER + game.turn;
    }
    GameStateData {
        white_player: game.white_player,
        black_player: game.black_player,
        board: game.board.clone(),
        turn: game.turn,
        status: game.status,
        move_timeout: game.move_timeout,
        castle_rights: game.castle_rights,
        en_passant_idx: game.en_passant_idx,
        pending_src_idx: square_idx(mv.from_x, mv.from_y),
        pending_dst_idx: square_idx(mv.to_x, mv.to_y),
        pending_promo: mv.promo_piece,
        recent_castle: 0,
        draw_state,
        move_log: game.move_log.clone(),
    }
}

fn apply_move_to_state(
    game: &GameStateData,
    mv: MoveSpec,
    allow_protocol_nonstandard: bool,
) -> Result<GameStateData, OrchestratorError> {
    let effective_turn = if game.draw_state < NORMAL { 1 - game.turn } else { game.turn };
    let next = if allow_protocol_nonstandard {
        apply_protocol_move(
            &ProtocolState {
                board: game.board.clone(),
                turn: effective_turn,
                castle_rights: game.castle_rights,
                en_passant_idx: game.en_passant_idx,
            },
            ProtocolMoveSpec { from_x: mv.from_x, from_y: mv.from_y, to_x: mv.to_x, to_y: mv.to_y, promo_piece: mv.promo_piece },
        )
    } else {
        apply_standard_chess_move(
            &ProtocolState {
                board: game.board.clone(),
                turn: effective_turn,
                castle_rights: game.castle_rights,
                en_passant_idx: game.en_passant_idx,
            },
            ProtocolMoveSpec { from_x: mv.from_x, from_y: mv.from_y, to_x: mv.to_x, to_y: mv.to_y, promo_piece: mv.promo_piece },
        )
    }
    .map_err(|err| {
        if allow_protocol_nonstandard {
            OrchestratorError(err.to_string())
        } else {
            OrchestratorError(format!("{err}. Use Force Move to follow the broader protocol path."))
        }
    })?;

    let mut move_log = game.move_log.clone();
    move_log.push(mv.label());
    Ok(GameStateData {
        white_player: game.white_player,
        black_player: game.black_player,
        board: next.board,
        turn: 1 - game.turn,
        status: game.status,
        move_timeout: game.move_timeout,
        castle_rights: next.castle_rights,
        en_passant_idx: next.en_passant_idx,
        pending_src_idx: OFFBOARD,
        pending_dst_idx: OFFBOARD,
        pending_promo: 0,
        recent_castle: next.recent_castle,
        draw_state: game.draw_state,
        move_log,
    })
}

fn apply_worker_state(
    worker: WorkerKind,
    game: &GameStateData,
    mv: MoveSpec,
    allow_protocol_nonstandard: bool,
) -> Result<GameStateData, OrchestratorError> {
    let mut next = apply_move_to_state(game, mv, allow_protocol_nonstandard)?;
    next.castle_rights = match worker {
        WorkerKind::Pawn | WorkerKind::Knight | WorkerKind::Diag => game.castle_rights,
        WorkerKind::Vert | WorkerKind::Horiz => {
            let mut castle_rights = game.castle_rights;
            let from_idx = square_idx(mv.from_x, mv.from_y);
            let to_idx = square_idx(mv.to_x, mv.to_y);
            if from_idx == 0 || to_idx == 0 {
                castle_rights[1] = 0;
            }
            if from_idx == 7 || to_idx == 7 {
                castle_rights[0] = 0;
            }
            if from_idx == 56 || to_idx == 56 {
                castle_rights[3] = 0;
            }
            if from_idx == 63 || to_idx == 63 {
                castle_rights[2] = 0;
            }
            castle_rights
        }
        WorkerKind::King | WorkerKind::Castle => {
            let mut castle_rights = game.castle_rights;
            let moving_piece = game.board[square_idx(mv.from_x, mv.from_y) as usize];
            let moving_is_black = moving_piece > 8;
            if moving_is_black {
                castle_rights[2] = 0;
                castle_rights[3] = 0;
            } else {
                castle_rights[0] = 0;
                castle_rights[1] = 0;
            }
            castle_rights
        }
        WorkerKind::CastleChallenge => {
            return Err(OrchestratorError("castle challenge apply is not modeled as a direct player move".to_string()));
        }
    };
    if worker == WorkerKind::Castle {
        return Ok(next);
    }

    let target_piece = game.board[square_idx(mv.to_x, mv.to_y) as usize];
    let target_num = i64::from(target_piece);
    let is_draw_claim_mode = game.draw_state < NORMAL;
    let effective_turn = if is_draw_claim_mode { 1 - game.turn } else { game.turn };

    let mut next_status = game.status;
    if game.recent_castle != CLEAR {
        next_status = if game.turn == WHITE { WWIN } else { BWIN };
    } else if is_draw_claim_mode {
        if effective_turn == WHITE && target_num == 14 {
            next_status = if game.turn == WHITE { WWIN } else { BWIN };
        }
        if effective_turn == BLACK && target_num == 6 {
            next_status = if game.turn == WHITE { WWIN } else { BWIN };
        }
    } else {
        let moving_piece = game.board[square_idx(mv.from_x, mv.from_y) as usize];
        let moving_is_black = moving_piece > 8;
        if !moving_is_black && target_num == 14 {
            next_status = WWIN;
        }
        if moving_is_black && target_num == 6 {
            next_status = BWIN;
        }
    }

    let mut next_draw_state = game.draw_state;
    if game.draw_state == CLAIMED {
        next_draw_state = DEFENSE;
    } else if game.draw_state == DEFENSE && next_status == LIVE {
        next_status = if game.turn == WHITE { BWIN } else { WWIN };
    }

    next.status = next_status;
    next.draw_state = next_draw_state;
    Ok(next)
}

fn sign_builder_input<T: AsRef<Transaction>>(tx: &MutableTransaction<T>, input_index: usize, keypair: &Keypair) -> Vec<u8> {
    let reused_values = SigHashReusedValuesUnsync::new();
    let sighash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_index, SIG_HASH_ALL, &reused_values);
    let signature = keypair.sign_schnorr(Message::from_digest(sighash.as_bytes()));
    let mut encoded = signature.as_ref().to_vec();
    encoded.push(SIG_HASH_ALL.to_u8());
    encoded
}

fn load_argent_artifact() -> Result<Artifact, OrchestratorError> {
    let artifact: Artifact = serde_json::from_str(include_str!("../../build/artifact.json"))
        .map_err(|err| OrchestratorError(format!("failed to load pinned Argent artifact: {err}")))?;
    artifact.check_consistency().map_err(|err| OrchestratorError(format!("invalid pinned Argent artifact: {err}")))?;
    Ok(artifact)
}

fn blake2b(data: &[u8]) -> Hash {
    Hash::from_slice(Blake2bParams::new().hash_length(32).to_state().update(data).finalize().as_bytes())
}

fn file_char(x: i64) -> char {
    (b'a' + (x as u8)) as char
}

fn rank_char(y: i64) -> char {
    (b'1' + (y as u8)) as char
}

fn standard_board() -> Vec<u8> {
    vec![
        0x04, 0x02, 0x03, 0x05, 0x06, 0x03, 0x02, 0x04, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x0c, 0x0a, 0x0b, 0x0d, 0x0e, 0x0b, 0x0a,
        0x0c,
    ]
}

fn approx_expected_score(diff: i64) -> i64 {
    let abs_diff = diff.abs();
    let favored_expected = if abs_diff < 75 {
        500
    } else if abs_diff < 150 {
        600
    } else if abs_diff < 250 {
        700
    } else if abs_diff < 400 {
        820
    } else if abs_diff < 600 {
        910
    } else if abs_diff < 800 {
        970
    } else {
        990
    };

    if diff < 0 {
        favored_expected
    } else if diff > 0 {
        1000 - favored_expected
    } else {
        500
    }
}

fn approx_updated_rating(self_rating: i64, opp_rating: i64, actual_score: i64) -> i64 {
    let expected = approx_expected_score(opp_rating - self_rating);
    self_rating + ((32 * (actual_score - expected)) / 1000)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_txs_can_play_a_short_game_end_to_end() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x31, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x32, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");

        white.send_game_invite(&black).expect("white sends invite");
        let invite_mail = black.inbox();
        assert!(matches!(invite_mail.as_slice(), [OffchainMessage { kind: OffchainMessageKind::GameInvite { .. }, .. }]));

        black.accept_game_invite(&white).expect("black accepts invite");
        let accepted_mail = white.inbox();
        assert!(matches!(accepted_mail.as_slice(), [OffchainMessage { kind: OffchainMessageKind::InviteAccepted { .. }, .. }]));

        white.start_game(&black).expect("start game tx passes");
        let started_mail_white = white.inbox();
        let started_mail = black.inbox();
        assert!(matches!(started_mail_white.as_slice(), [OffchainMessage { kind: OffchainMessageKind::GameStarted { .. }, .. }]));
        assert!(matches!(started_mail.as_slice(), [OffchainMessage { kind: OffchainMessageKind::GameStarted { .. }, .. }]));

        white.submit_move(MoveSpec::new(4, 1, 4, 3)).expect("white e2e4 txs pass");
        let move_mail = black.inbox();
        assert!(matches!(
            move_mail.as_slice(),
            [OffchainMessage { kind: OffchainMessageKind::MoveNotice { ref move_label, .. }, .. }] if move_label == "e2e4"
        ));

        black.submit_move(MoveSpec::new(6, 7, 5, 5)).expect("black g8f6 txs pass");
        let reply_mail = white.inbox();
        assert!(matches!(
            reply_mail.as_slice(),
            [OffchainMessage { kind: OffchainMessageKind::MoveNotice { ref move_label, .. }, .. }] if move_label == "g8f6"
        ));

        white.submit_move(MoveSpec::new(5, 0, 2, 3)).expect("white bishop f1c4 txs pass");
        black.inbox();

        black.surrender().expect("black surrender tx passes");
        black.request_settlement(&white, GameResult::WhiteWin).expect("black requests settlement");
        let settlement_request = white.inbox();
        assert!(matches!(
            settlement_request.as_slice(),
            [OffchainMessage { kind: OffchainMessageKind::SettlementRequest { result: GameResult::WhiteWin, .. }, .. }]
        ));

        white.settle(&black, GameResult::WhiteWin).expect("settlement txs pass");
        let settlement_notice = black.inbox();
        assert!(settlement_notice
            .iter()
            .any(|message| { matches!(message.kind, OffchainMessageKind::SettlementNotice { result: GameResult::WhiteWin }) }));

        {
            let arena = shared.borrow();
            let white_state = arena.player_account_snapshot(&white.player).expect("white player remains after settlement");
            let black_state = arena.player_account_snapshot(&black.player).expect("black player remains after settlement");
            assert_eq!(white_state.value, 2_000);
            assert_eq!(black_state.value, 1_000);
        }

        white.retire().expect("retire tx passes");

        let arena = shared.borrow();
        let game = arena.active_game_snapshot();
        assert!(game.is_none());
        let white_state = arena.player_account_snapshot(&white.player);
        let black_state = arena.player_account_snapshot(&black.player).expect("black player remains");
        assert!(white_state.is_err());
        assert_eq!(black_state.open_games, 0);
        assert_eq!(black_state.losses, 1);
        assert_eq!(arena.history().len(), 13);
        for submitted in arena.history() {
            let tx = arena
                .transactions()
                .iter()
                .find(|tx| tx.id() == submitted.transaction_id)
                .expect("history entry references an executed transaction");
            assert_eq!(submitted.input_outpoints, tx.inputs.iter().map(|input| input.previous_outpoint).collect::<Vec<_>>());
            assert_eq!(
                submitted.output_outpoints,
                tx.outputs.iter().enumerate().map(|(index, _)| TransactionOutpoint::new(tx.id(), index as u32)).collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn illegal_move_does_not_leave_the_game_stuck() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x51, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x52, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");
        white.start_game(&black).expect("start game tx passes");

        let (history_before, txs_before, game_before) = {
            let arena = shared.borrow();
            (arena.history().len(), arena.transactions().len(), arena.active_game_snapshot().expect("active game exists"))
        };

        let err = white.submit_move(MoveSpec::new(4, 1, 4, 4)).expect_err("illegal e2e5 should fail");
        assert!(err.to_string().contains("Use Force Move"), "unexpected error: {err}");

        {
            let arena = shared.borrow();
            let game_after = arena.active_game_snapshot().expect("active game still exists");
            assert_eq!(arena.history().len(), history_before);
            assert_eq!(arena.transactions().len(), txs_before);
            assert_eq!(game_after.turn, game_before.turn);
            assert_eq!(game_after.status, game_before.status);
            assert_eq!(game_after.board, game_before.board);
        }

        white.submit_move(MoveSpec::new(4, 1, 4, 3)).expect("legal e2e4 should still pass");
        {
            let arena = shared.borrow();
            let game_after = arena.active_game_snapshot().expect("active game exists");
            assert_eq!(game_after.turn, Side::Black);
            assert_eq!(arena.history().len(), history_before + 2);
            assert_eq!(arena.transactions().len(), txs_before + 2);
        }
    }

    #[test]
    fn forced_illegal_move_can_be_timed_out_and_settled() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x61, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x62, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");
        white.start_game(&black).expect("start game tx passes");

        let forced = white.force_move(MoveSpec::new(4, 1, 4, 4)).expect("forced illegal move should route");
        assert_eq!(forced.len(), 1);
        assert_eq!(forced[0].action, "route");

        let notice = black.inbox();
        assert!(notice.iter().any(|message| {
            matches!(message.kind, OffchainMessageKind::TimeoutClaimAvailable { result: GameResult::BlackWin, .. })
        }));

        {
            let arena = shared.borrow();
            let game = arena.active_game_snapshot().expect("worker transit should be visible");
            assert!(game.phase.starts_with("worker:"));
        }

        black.claim_timeout().expect("black claims timeout");
        let settlement_request = white.inbox();
        assert!(settlement_request
            .iter()
            .any(|message| { matches!(message.kind, OffchainMessageKind::SettlementRequest { result: GameResult::BlackWin, .. }) }));

        white.settle(&black, GameResult::BlackWin).expect("timeout win settles");
        {
            let arena = shared.borrow();
            let white_state = arena.player_account_snapshot(&white.player).expect("white remains");
            let black_state = arena.player_account_snapshot(&black.player).expect("black remains");
            assert_eq!(white_state.losses, 1);
            assert_eq!(black_state.wins, 1);
            assert_eq!(white_state.open_games, 0);
            assert_eq!(black_state.open_games, 0);
            assert_eq!(arena.active_game_snapshot(), None);
        }
    }

    #[test]
    fn actual_txs_can_offer_accept_and_settle_a_draw() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x63, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x64, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");
        white.start_game(&black).expect("start game tx passes");

        let move_txs = white.offer_draw(MoveSpec::new(4, 1, 4, 3)).expect("draw offer move passes");
        assert_eq!(move_txs.len(), 2);
        let black_notices = black.inbox();
        assert!(black_notices.iter().any(|message| {
            matches!(message.kind, OffchainMessageKind::MoveNotice { ref move_label, .. } if move_label == "e2e4")
        }));
        assert!(black_notices
            .iter()
            .any(|message| matches!(message.kind, OffchainMessageKind::DrawOffered { ref actor } if actor == "white")));

        {
            let arena = shared.borrow();
            let game = arena.game.as_ref().expect("Mux remains active after draw offer");
            assert_eq!(game.turn, BLACK);
            assert_eq!(game.draw_state, WOFFER);
        }

        black.accept_draw().expect("black accepts the draw");
        assert!(white
            .inbox()
            .iter()
            .any(|message| matches!(message.kind, OffchainMessageKind::DrawAccepted { ref actor } if actor == "black")));
        {
            let arena = shared.borrow();
            let game = arena.game.as_ref().expect("terminal Mux remains until settlement");
            assert_eq!(game.status, DRAW);
            assert_eq!(game.draw_state, NORMAL);
            assert_eq!(arena.history().last().expect("accept transaction").action, "draw_accept");
        }

        white.settle(&black, GameResult::Draw).expect("accepted draw settles");
        let arena = shared.borrow();
        let white_state = arena.player_account_snapshot(&white.player).expect("white remains");
        let black_state = arena.player_account_snapshot(&black.player).expect("black remains");
        assert_eq!(white_state.draws, 1);
        assert_eq!(black_state.draws, 1);
        assert_eq!(white_state.value, 1_500);
        assert_eq!(black_state.value, 1_500);
    }

    #[test]
    fn actual_txs_execute_the_draw_claim_defense_game() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x65, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x66, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");
        white.start_game(&black).expect("start game tx passes");

        white.claim_draw().expect("white claims a draw");
        assert!(black
            .inbox()
            .iter()
            .any(|message| matches!(message.kind, OffchainMessageKind::DrawClaimed { ref actor } if actor == "white")));
        {
            let arena = shared.borrow();
            let game = arena.game.as_ref().expect("claimed game remains active");
            assert_eq!(game.turn, BLACK);
            assert_eq!(game.draw_state, CLAIMED);
        }

        black.submit_move(MoveSpec::new(1, 0, 2, 2)).expect("black controls a white proof move");
        {
            let arena = shared.borrow();
            let game = arena.game.as_ref().expect("defense game remains active");
            assert_eq!(game.turn, WHITE);
            assert_eq!(game.draw_state, DEFENSE);
            assert_eq!(game.board[1], 0);
            assert_eq!(game.board[18], 0x02);
        }

        white.submit_move(MoveSpec::new(1, 7, 2, 5)).expect("white controls a black defense move");
        {
            let arena = shared.borrow();
            let game = arena.game.as_ref().expect("failed claim remains until settlement");
            assert_eq!(game.status, BWIN);
            assert_eq!(game.board[57], 0);
            assert_eq!(game.board[42], 0x0a);
        }

        white.settle(&black, GameResult::BlackWin).expect("failed draw claim settles");
        let arena = shared.borrow();
        assert_eq!(arena.player_account_snapshot(&white.player).expect("white remains").losses, 1);
        assert_eq!(arena.player_account_snapshot(&black.player).expect("black remains").wins, 1);
    }

    #[test]
    fn actual_mux_timeout_requires_and_rewards_the_waiting_opponent() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x67, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x68, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");
        white.start_game(&black).expect("start game tx passes");

        let err = white.claim_timeout().expect_err("active player cannot claim own Mux timeout");
        assert!(err.0.contains("not entitled"), "unexpected error: {}", err.0);
        black.claim_timeout().expect("waiting black player claims Mux timeout");

        {
            let arena = shared.borrow();
            assert!(arena.game.is_none());
            assert_eq!(arena.active_settle.as_ref().expect("timeout creates Settle").status, BWIN);
            let timeout = arena.history().last().expect("timeout transaction is recorded");
            assert_eq!(timeout.action, "mux_timeout");
            assert_eq!(timeout.signer_names, ["black"]);
        }

        white.settle(&black, GameResult::BlackWin).expect("Mux timeout settles");
        let arena = shared.borrow();
        assert_eq!(arena.player_account_snapshot(&white.player).expect("white remains").losses, 1);
        assert_eq!(arena.player_account_snapshot(&black.player).expect("black remains").wins, 1);
    }

    #[test]
    fn actual_maintenance_txs_rebalance_and_fork_contracts() {
        let mut arena = TxArena::new().expect("actual arena builds");
        arena.rebalance_league(0, 1_200).expect("admin rebalances the League lane");
        arena.fork_league(0, 500, 700).expect("admin forks the League lane");
        assert_eq!(arena.league_lane_count(), 2);
        assert_eq!(arena.league_lane_values(), [500, 700]);

        let mut player = SigningPlayer::from_seed("player", 0x69);
        arena.register_player_on_lane(&mut player, 1).expect("player registers through the selected forked lane");
        arena.rebalance_player(&player, 2_500).expect("owner rebalances the Player");
        assert_eq!(arena.player_account_snapshot(&player).expect("player remains").value, 2_500);
        assert_eq!(
            arena.history().iter().map(|submission| submission.action).collect::<Vec<_>>(),
            ["league_rebalance", "league_fork", "register_player", "player_rebalance"]
        );

        let indexer = crate::indexer::ChessIndexer::load().expect("indexer loads");
        let chain = indexer.index_transactions(arena.transactions(), arena.covenant_id()).expect("maintenance txs index");
        assert_eq!(chain.league_lane_count, 2);
        assert_eq!(chain.players.len(), 1);
        assert_eq!(chain.players[0].value, 2_500);
        assert!(chain.warnings.is_empty(), "indexer warnings: {:?}", chain.warnings);
    }

    #[test]
    fn actual_txs_can_capture_the_enemy_king() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x71, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x72, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");
        white.start_game(&black).expect("start game tx passes");

        {
            let mut arena = shared.borrow_mut();
            let game = arena.game.as_mut().expect("active game exists");
            let mut board = vec![0u8; 64];
            board[0] = 0x05;
            board[24] = 0x0e;
            game.board = board;
            game.turn = Side::White as i64;
            game.status = LIVE;
            game.castle_rights = [1, 1, 1, 1];
            game.en_passant_idx = OFFBOARD;
            game.pending_src_idx = OFFBOARD;
            game.pending_dst_idx = OFFBOARD;
            game.pending_promo = 0;
            game.recent_castle = CLEAR;
            game.draw_state = NORMAL;
            game.move_log.clear();
        }

        let err = white.submit_move(MoveSpec::new(0, 0, 0, 3)).expect_err("standard submit should reject king capture");
        assert!(err.0.contains("Force Move"), "unexpected error: {}", err.0);

        white.force_move(MoveSpec::new(0, 0, 0, 3)).expect("forced king capture txs pass");

        let arena = shared.borrow();
        let game = arena.active_game_snapshot().expect("active game remains until settlement");
        assert_eq!(game.status, WWIN);
        assert_eq!(game.turn, Side::Black);
        assert_eq!(game.board[24], 0x05);
        assert_eq!(game.board[0], 0x00);
    }

    #[test]
    fn opponent_can_reply_normally_after_castle() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x81, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x82, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");
        white.start_game(&black).expect("start game tx passes");

        white.submit_move(MoveSpec::new(4, 1, 4, 3)).expect("white e2e4 tx passes");
        black.submit_move(MoveSpec::new(4, 6, 4, 4)).expect("black e7e5 tx passes");
        white.submit_move(MoveSpec::new(6, 0, 5, 2)).expect("white g1f3 tx passes");
        black.submit_move(MoveSpec::new(1, 7, 2, 5)).expect("black b8c6 tx passes");
        white.submit_move(MoveSpec::new(5, 0, 4, 1)).expect("white f1e2 tx passes");
        black.submit_move(MoveSpec::new(6, 7, 5, 5)).expect("black g8f6 tx passes");
        white.submit_move(MoveSpec::new(4, 0, 6, 0)).expect("white castles kingside");

        {
            let arena = shared.borrow();
            let game = arena.active_game_snapshot().expect("active game exists after castle");
            assert_eq!(game.turn, Side::Black);
            assert_eq!(game.board[4], 0x00);
            assert_eq!(game.board[5], 0x04);
            assert_eq!(game.board[6], 0x06);
            assert_eq!(game.board[7], 0x00);
        }

        black.submit_move(MoveSpec::new(0, 6, 0, 5)).expect("black a7a6 reply should pass after castle");

        let arena = shared.borrow();
        let game = arena.active_game_snapshot().expect("active game exists after reply");
        assert_eq!(game.turn, Side::White);
        assert_eq!(game.board[48], 0x00);
        assert_eq!(game.board[40], 0x09);
    }

    #[test]
    fn actual_txs_can_prove_that_a_castle_crossed_check() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x83, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x84, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");
        white.start_game(&black).expect("start game tx passes");

        white.submit_move(MoveSpec::new(4, 1, 4, 2)).expect("white e2e3");
        black.submit_move(MoveSpec::new(4, 6, 4, 4)).expect("black e7e5");
        white.submit_move(MoveSpec::new(6, 0, 5, 2)).expect("white g1f3");
        black.submit_move(MoveSpec::new(0, 6, 0, 5)).expect("black a7a6");
        white.submit_move(MoveSpec::new(5, 0, 4, 1)).expect("white f1e2");
        black.submit_move(MoveSpec::new(0, 5, 0, 4)).expect("black a6a5");
        white.submit_move(MoveSpec::new(3, 1, 3, 3)).expect("white d2d4");
        black.submit_move(MoveSpec::new(5, 7, 1, 3)).expect("black f8b4 check");
        white.force_move(MoveSpec::new(4, 0, 6, 0)).expect("protocol allows white to commit the challenged castle");

        let challenge = black.challenge_castle(MoveSpec::new(1, 3, 4, 0)).expect("black proves the start square was attacked");
        assert_eq!(
            challenge.iter().map(|submission| submission.action).collect::<Vec<_>>(),
            ["castle_challenge_route", "castle_challenge_prepare", "castle_challenge_apply"]
        );
        {
            let arena = shared.borrow();
            let game = arena.game.as_ref().expect("terminal Mux remains until settlement");
            assert_eq!(game.status, BWIN);
            assert_eq!(game.turn, WHITE);
            assert_eq!(game.recent_castle, CLEAR);
            assert_eq!(game.board[4], 0x0b);
        }

        white.settle(&black, GameResult::BlackWin).expect("successful castle challenge settles");
        let arena = shared.borrow();
        assert_eq!(arena.player_account_snapshot(&white.player).expect("white remains").losses, 1);
        assert_eq!(arena.player_account_snapshot(&black.player).expect("black remains").wins, 1);
    }

    #[test]
    fn invalid_castle_challenge_commits_to_a_timeout_path() {
        let shared = TxArena::shared().expect("actual arena builds");
        let mut white = TxOrchestrator::new("white", 0x85, shared.clone());
        let mut black = TxOrchestrator::new("black", 0x86, shared.clone());

        white.register().expect("white register tx passes");
        black.register().expect("black register tx passes");
        white.start_game(&black).expect("start game tx passes");
        white.submit_move(MoveSpec::new(4, 1, 4, 3)).expect("white e2e4");
        black.submit_move(MoveSpec::new(4, 6, 4, 4)).expect("black e7e5");
        white.submit_move(MoveSpec::new(6, 0, 5, 2)).expect("white g1f3");
        black.submit_move(MoveSpec::new(1, 7, 2, 5)).expect("black b8c6");
        white.submit_move(MoveSpec::new(5, 0, 4, 1)).expect("white f1e2");
        black.submit_move(MoveSpec::new(6, 7, 5, 5)).expect("black g8f6");
        white.submit_move(MoveSpec::new(4, 0, 6, 0)).expect("white castles kingside");

        let err = black.challenge_castle(MoveSpec::new(5, 5, 6, 0)).expect_err("invalid knight proof is rejected before commit");
        assert!(err.0.contains("Illegal move") || err.0.contains("apply"), "unexpected error: {}", err.0);
        let forced = black.force_castle_challenge(MoveSpec::new(5, 5, 6, 0)).expect("forced invalid challenge commits through prep");
        assert_eq!(
            forced.iter().map(|submission| submission.action).collect::<Vec<_>>(),
            ["castle_challenge_route", "castle_challenge_prepare"]
        );
        {
            let arena = shared.borrow();
            let game = arena.active_game_snapshot().expect("prepared worker remains active");
            assert_eq!(game.phase, "worker:Knight");
        }
        assert!(white.inbox().iter().any(|message| {
            matches!(
                message.kind,
                OffchainMessageKind::TimeoutClaimAvailable { result: GameResult::WhiteWin, worker: WorkerKind::Knight, .. }
            )
        }));

        white.claim_timeout().expect("white routes the invalid challenge to Settle");
        white.settle(&black, GameResult::WhiteWin).expect("invalid challenge timeout settles");
        let arena = shared.borrow();
        assert_eq!(arena.player_account_snapshot(&white.player).expect("white remains").wins, 1);
        assert_eq!(arena.player_account_snapshot(&black.player).expect("black remains").losses, 1);
    }
}
