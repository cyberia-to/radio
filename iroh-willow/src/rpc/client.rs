//! API for managing iroh spaces
//!
//! iroh spaces is an implementation of the [Willow] protocol.
//! The main entry point is the [`Client`].
//!
//! [Willow]: https://willowprotocol.org/

use std::{
    collections::HashMap,
    pin::Pin,
    task::{ready, Context, Poll},
};

use anyhow::{anyhow, Result};
use bytes::Bytes;
use futures_lite::{Stream, StreamExt};
use iroh::{EndpointAddr, EndpointId};
use iroh_blobs::Hash;
use serde::{Deserialize, Serialize};
use tokio_stream::{StreamMap, StreamNotifyClose};

use crate::{
    form::{AuthForm, SubspaceForm, TimestampForm},
    interest::{
        AreaOfInterestSelector, CapSelector, CapabilityPack, DelegateTo, Interests, RestrictArea,
    },
    proto::{
        data_model::{AuthorisedEntry, Path, SubspaceId},
        grouping::{Area, Range3d},
        keys::{NamespaceId, NamespaceKind, UserId},
        meadowcap::{AccessMode, SecretKey},
    },
    rpc::proto::*,
    session::{
        intents::{serde_encoding::Event, Completion, IntentUpdate},
        SessionInit, SessionMode,
    },
    store::traits::{StoreEvent, SubscribeParams},
};

/// Type alias for a memory-backed client.
pub type MemClient = Client;

/// Iroh Willow client.
#[derive(Debug, Clone)]
pub struct Client {
    pub(super) rpc: irpc::Client<Request>,
}

impl Client {
    pub fn new(rpc: irpc::Client<Request>) -> Self {
        Self { rpc }
    }

    /// Create a new namespace in the Willow store.
    pub async fn create(&self, kind: NamespaceKind, owner: UserId) -> Result<Space> {
        let req = CreateNamespaceRequest { kind, owner };
        let res = self.rpc.rpc(req).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        Ok(Space::new(self.rpc.clone(), res.0))
    }

    /// Create a new user in the Willow store.
    pub async fn create_user(&self) -> Result<UserId> {
        let req = CreateUserRequest;
        let res: RpcResult<CreateUserResponse> = self.rpc.rpc(req).await.map_err(|e| anyhow::anyhow!("{e}"))?;
        let res = res?;
        Ok(res.0)
    }

    /// Delegate capabilities to another user.
    pub async fn delegate_caps(
        &self,
        from: CapSelector,
        access_mode: AccessMode,
        to: DelegateTo,
    ) -> Result<Vec<CapabilityPack>> {
        let req = DelegateCapsRequest {
            from,
            access_mode,
            to,
        };
        let res = self.rpc.rpc(req).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        Ok(res.0)
    }

    /// Import capabilities.
    pub async fn import_caps(&self, caps: Vec<CapabilityPack>) -> Result<()> {
        let req = ImportCapsRequest { caps };
        self.rpc.rpc(req).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        Ok(())
    }

    /// Import a ticket and start to synchronize.
    pub async fn import_and_sync(
        &self,
        ticket: SpaceTicket,
        mode: SessionMode,
    ) -> Result<(Space, SyncHandleSet)> {
        if ticket.caps.is_empty() {
            anyhow::bail!("Invalid ticket: Does not include any capabilities");
        }
        let mut namespaces = ticket.caps.iter().map(|pack| pack.namespace());
        let namespace = namespaces.next().expect("just checked");
        if !namespaces.all(|n| n == namespace) {
            anyhow::bail!("Invalid ticket: Capabilities do not all refer to the same namespace");
        }

        self.import_caps(ticket.caps).await?;
        let interests = Interests::builder().add_full_cap(CapSelector::any(namespace));
        let init = SessionInit::new(interests, mode);
        let mut intents = SyncHandleSet::default();
        for addr in ticket.nodes {
            let node_id = addr.id;
            self.add_addr(addr.clone()).await?;
            let intent = self.sync_with_peer(node_id, init.clone()).await?;
            intents.insert(node_id, intent)?;
        }
        let space = Space::new(self.rpc.clone(), namespace);
        Ok((space, intents))
    }

    /// Synchronize with a peer.
    pub async fn sync_with_peer(&self, peer: EndpointId, init: SessionInit) -> Result<SyncHandle> {
        let req = SyncWithPeerRequest { peer, init };
        let (update_tx, mut event_rx) = self.rpc.bidi_streaming(req, 32, 32).await
            .map_err(|e| anyhow::anyhow!("{e}"))?;

        let (mapped_tx, mapped_rx) = tokio::sync::mpsc::channel(32);
        tokio::task::spawn(async move {
            while let Ok(Some(res)) = event_rx.recv().await {
                let res: RpcResult<SyncWithPeerResponse> = res;
                let event = match res {
                    Ok(SyncWithPeerResponse::Event(event)) => event,
                    Ok(SyncWithPeerResponse::Started) => Event::ReconciledAll,
                    Err(e) => Event::Abort {
                        error: e.to_string(),
                    },
                };
                if mapped_tx.send(event).await.is_err() {
                    break;
                }
            }
        });

        let event_rx: EventReceiver = Box::pin(tokio_stream::wrappers::ReceiverStream::new(mapped_rx));

        let (mapped_update_tx, mut mapped_update_rx) = tokio::sync::mpsc::channel::<IntentUpdate>(32);
        tokio::task::spawn(async move {
            while let Some(update) = mapped_update_rx.recv().await {
                if update_tx.send(SyncWithPeerUpdate(update)).await.is_err() {
                    break;
                }
            }
        });

        let update_tx: UpdateSender = Box::pin(futures_util::sink::unfold(mapped_update_tx, |tx, item| async move {
            tx.send(item).await.map_err(|e| anyhow::anyhow!("{e}"))?;
            Ok(tx)
        }));

        Ok(SyncHandle::new(update_tx, event_rx, Default::default()))
    }

    /// Import a secret into the Willow store.
    pub async fn import_secret(&self, secret: impl Into<SecretKey>) -> Result<()> {
        let req = InsertSecretRequest {
            secret: secret.into(),
        };
        self.rpc.rpc(req).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        Ok(())
    }

    /// Fetches the [`EndpointAddr`] for this endpoint.
    pub async fn addr(&self) -> Result<EndpointAddr> {
        let addr = self.rpc.rpc(AddrRequest).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        Ok(addr)
    }

    /// Adds a known endpoint address.
    pub async fn add_addr(&self, addr: EndpointAddr) -> Result<()> {
        self.rpc.rpc(AddAddrRequest { addr }).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        Ok(())
    }
}

/// A space to store entries in.
#[derive(Debug, Clone)]
pub struct Space {
    rpc: irpc::Client<Request>,
    namespace_id: NamespaceId,
}

impl Space {
    fn new(rpc: irpc::Client<Request>, namespace_id: NamespaceId) -> Self {
        Self { rpc, namespace_id }
    }

    fn spaces(&self) -> Client {
        Client { rpc: self.rpc.clone() }
    }

    /// Returns the identifier for this space.
    pub fn namespace_id(&self) -> NamespaceId {
        self.namespace_id
    }

    async fn insert(&self, entry: EntryForm, payload: PayloadForm) -> Result<InsertEntrySuccess> {
        let form = FullEntryForm {
            namespace_id: self.namespace_id,
            subspace_id: entry.subspace_id,
            path: entry.path,
            timestamp: entry.timestamp,
            payload,
        };
        let auth = entry.auth;
        let req = InsertEntryRequest { entry: form, auth };
        let res = self.rpc.rpc(req).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        Ok(res)
    }

    /// Inserts a new entry, with the payload set to the hash of a blob.
    pub async fn insert_hash(&self, entry: EntryForm, payload: Hash) -> Result<InsertEntrySuccess> {
        let payload = PayloadForm::Checked(payload);
        self.insert(entry, payload).await
    }

    /// Inserts a new entry, with the payload imported from a byte string.
    pub async fn insert_bytes(
        &self,
        blobs: &iroh_blobs::api::Store,
        entry: EntryForm,
        payload: impl Into<Bytes>,
    ) -> Result<InsertEntrySuccess> {
        let tag = blobs
            .blobs()
            .add_bytes(payload.into())
            .temp_tag()
            .await?;
        self.insert_hash(entry, tag.hash()).await
    }

    /// Ingest an authorised entry.
    pub async fn ingest(&self, authorised_entry: AuthorisedEntry) -> Result<()> {
        let req = IngestEntryRequest { authorised_entry };
        self.rpc.rpc(req).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        Ok(())
    }

    /// Get a single entry.
    pub async fn get_one(
        &self,
        subspace: SubspaceId,
        path: Path,
    ) -> Result<Option<AuthorisedEntry>> {
        let req = GetEntryRequest {
            namespace: self.namespace_id,
            subspace,
            path,
        };
        let entry = self.rpc.rpc(req).await.map_err(|e| anyhow::anyhow!("{e}"))??;
        Ok(entry.0.map(Into::into))
    }

    /// Get entries by range.
    pub async fn get_many(
        &self,
        range: Range3d,
    ) -> Result<impl Stream<Item = Result<AuthorisedEntry>>> {
        let req = GetEntriesRequest {
            namespace: self.namespace_id,
            range,
        };
        let rx = self.rpc.server_streaming(req, 64).await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(rx.into_stream()
            .map(|res| match res {
                Ok(Ok(r)) => Ok(r.0),
                Ok(Err(e)) => Err(anyhow::anyhow!("{e}")),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            }))
    }

    /// Syncs with a peer and quit the session after a single reconciliation.
    pub async fn sync_once(
        &self,
        node: EndpointId,
        areas: AreaOfInterestSelector,
    ) -> Result<SyncHandle> {
        let cap = CapSelector::any(self.namespace_id);
        let interests = Interests::builder().add(cap, areas);
        let init = SessionInit::reconcile_once(interests);
        self.spaces().sync_with_peer(node, init).await
    }

    /// Sync with a peer and keep sending and receiving live updates.
    pub async fn sync_continuously(
        &self,
        node: EndpointId,
        areas: AreaOfInterestSelector,
    ) -> Result<SyncHandle> {
        let cap = CapSelector::any(self.namespace_id);
        let interests = Interests::builder().add(cap, areas);
        let init = SessionInit::continuous(interests);
        self.spaces().sync_with_peer(node, init).await
    }

    /// Share access to this space with another user.
    pub async fn share(
        &self,
        receiver: UserId,
        access_mode: AccessMode,
        restrict_area: RestrictArea,
    ) -> Result<SpaceTicket> {
        let caps = self
            .spaces()
            .delegate_caps(
                CapSelector::any(self.namespace_id),
                access_mode,
                DelegateTo::new(receiver, restrict_area),
            )
            .await?;
        let node_addr = self.spaces().addr().await?;
        Ok(SpaceTicket {
            caps,
            nodes: vec![node_addr],
        })
    }

    /// Subscribe to events concerning entries included by an `Area`.
    pub async fn subscribe_area(
        &self,
        area: Area,
        params: SubscribeParams,
    ) -> Result<impl Stream<Item = Result<StoreEvent>>> {
        let req = SubscribeRequest {
            namespace: self.namespace_id,
            area,
            params,
            initial_progress_id: None,
        };
        let rx = self.rpc.server_streaming(req, 1024).await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let stream = rx.into_stream()
            .map(|item| match item {
                Ok(Ok(event)) => Ok(event),
                Ok(Err(e)) => Err(anyhow::anyhow!("{e}")),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            });
        Ok(stream)
    }

    /// Resume a subscription using a progress ID obtained from a previous subscription.
    pub async fn resume_subscription(
        &self,
        progress_id: u64,
        area: Area,
        params: SubscribeParams,
    ) -> Result<impl Stream<Item = Result<StoreEvent>>> {
        let req = SubscribeRequest {
            namespace: self.namespace_id,
            area,
            params,
            initial_progress_id: Some(progress_id),
        };
        let rx = self.rpc.server_streaming(req, 1024).await
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let stream = rx.into_stream()
            .map(|item| match item {
                Ok(Ok(event)) => Ok(event),
                Ok(Err(e)) => Err(anyhow::anyhow!("{e}")),
                Err(e) => Err(anyhow::anyhow!("{e}")),
            });
        Ok(stream)
    }
}

/// A ticket to import and sync a space.
#[derive(Debug, Serialize, Deserialize)]
pub struct SpaceTicket {
    pub caps: Vec<CapabilityPack>,
    pub nodes: Vec<EndpointAddr>,
}

/// Handle to a synchronization intent.
#[derive(derive_more::Debug)]
pub struct SyncHandle {
    #[debug("UpdateSender")]
    update_tx: UpdateSender,
    #[debug("EventReceiver")]
    event_rx: EventReceiver,
    state: SyncProgress,
}

/// Sends updates into a reconciliation intent.
pub type UpdateSender = Pin<Box<dyn futures_util::Sink<IntentUpdate, Error = anyhow::Error> + Send + 'static>>;

/// Receives events for a reconciliation intent.
pub type EventReceiver = Pin<Box<dyn Stream<Item = Event> + Send + 'static>>;

impl SyncHandle {
    fn new(update_tx: UpdateSender, event_rx: EventReceiver, state: SyncProgress) -> Self {
        Self {
            update_tx,
            event_rx,
            state,
        }
    }

    /// Splits the `SyncHandle` into an update sender sink and event receiver stream.
    pub fn split(self) -> (UpdateSender, EventReceiver) {
        (self.update_tx, self.event_rx)
    }

    /// Waits for the intent to be completed.
    pub async fn complete(&mut self) -> Result<Completion> {
        let mut state = SyncProgress::default();
        while let Some(event) = self.event_rx.next().await {
            state.handle_event(&event);
            if state.is_ready() {
                break;
            }
        }
        state.into_completion()
    }

    /// Submit new synchronisation interests into the session.
    pub async fn add_interests(&mut self, interests: impl Into<Interests>) -> Result<()> {
        use futures_util::SinkExt;
        self.update_tx
            .send(IntentUpdate::AddInterests(interests.into()))
            .await?;
        Ok(())
    }
}

impl Stream for SyncHandle {
    type Item = Event;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(match ready!(Pin::new(&mut self.event_rx).poll_next(cx)) {
            None => None,
            Some(event) => {
                self.state.handle_event(&event);
                Some(event)
            }
        })
    }
}

/// Completion state for a [`SyncHandle`].
#[derive(Debug, Default)]
pub struct SyncProgress {
    partial: bool,
    complete: bool,
    failed: Option<String>,
}
impl SyncProgress {
    fn handle_event(&mut self, event: &Event) {
        match event {
            Event::ReconciledAll => self.complete = true,
            Event::Reconciled { .. } => self.partial = true,
            Event::Abort { error } => self.failed = Some(error.clone()),
            _ => {}
        }
    }

    fn is_ready(&self) -> bool {
        self.complete || self.failed.is_some()
    }

    fn into_completion(self) -> Result<Completion> {
        if let Some(error) = self.failed {
            Err(anyhow!(error))
        } else if self.complete {
            Ok(Completion::Complete)
        } else if self.partial {
            Ok(Completion::Partial)
        } else {
            Ok(Completion::Nothing)
        }
    }
}

/// Merges synchronisation intent handles into one struct.
#[derive(Default, derive_more::Debug)]
#[debug("MergedSyncHandle({:?})", self.event_rx.keys().collect::<Vec<_>>())]
pub struct SyncHandleSet {
    event_rx: StreamMap<EndpointId, StreamNotifyClose<EventReceiver>>,
    intents: HashMap<EndpointId, HandleState>,
}

#[derive(derive_more::Debug)]
struct HandleState {
    #[debug("UpdateSender")]
    update_tx: UpdateSender,
    state: SyncProgress,
}

impl SyncHandleSet {
    /// Add a sync intent to the set.
    pub fn insert(&mut self, peer: EndpointId, handle: SyncHandle) -> Result<(), IntentExistsError> {
        if let std::collections::hash_map::Entry::Vacant(e) = self.intents.entry(peer) {
            let SyncHandle {
                update_tx,
                event_rx,
                state,
            } = handle;
            self.event_rx.insert(peer, StreamNotifyClose::new(event_rx));
            e.insert(HandleState { update_tx, state });
            Ok(())
        } else {
            Err(IntentExistsError(peer))
        }
    }

    /// Removes a sync intent from the set.
    pub fn remove(&mut self, peer: &EndpointId) -> Option<SyncHandle> {
        self.event_rx.remove(peer).and_then(|event_rx| {
            self.intents.remove(peer).map(|state| {
                SyncHandle::new(
                    state.update_tx,
                    event_rx.into_inner().expect("unreachable"),
                    state.state,
                )
            })
        })
    }

    /// Submit new synchronisation interests into all sessions.
    pub async fn add_interests(&mut self, interests: impl Into<Interests>) -> Result<()> {
        let interests: Interests = interests.into();
        let futs = self.intents.values_mut().map(|intent| {
            use futures_util::SinkExt;
            intent
                .update_tx
                .send(IntentUpdate::AddInterests(interests.clone()))
        });
        futures_buffered::try_join_all(futs).await?;
        Ok(())
    }

    /// Wait for all intents to complete.
    pub async fn complete_all(mut self) -> HashMap<EndpointId, Result<Completion>> {
        let futs = self.intents.drain().map(|(node_id, state)| {
            let event_rx = self
                .event_rx
                .remove(&node_id)
                .expect("unreachable")
                .into_inner()
                .expect("unreachable");
            async move {
                let res = SyncHandle::new(state.update_tx, event_rx, state.state)
                    .complete()
                    .await;
                (node_id, res)
            }
        });
        let res = futures_buffered::join_all(futs).await;
        res.into_iter().collect()
    }
}

impl Stream for SyncHandleSet {
    type Item = (EndpointId, Event);

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            match ready!(Pin::new(&mut self.event_rx).poll_next(cx)) {
                None => break Poll::Ready(None),
                Some((peer, Some(event))) => break Poll::Ready(Some((peer, event))),
                Some((peer, None)) => {
                    self.intents.remove(&peer);
                    self.event_rx.remove(&peer);
                    continue;
                }
            }
        }
    }
}

/// Error returned when trying to insert a [`SyncHandle`] for a peer that is already in the set.
#[derive(Debug, thiserror::Error)]
#[error("The set already contains a sync intent for this peer.")]
pub struct IntentExistsError(pub EndpointId);

/// Form to insert a new entry
#[derive(Debug)]
pub struct EntryForm {
    pub auth: AuthForm,
    pub subspace_id: SubspaceForm,
    pub path: Path,
    pub timestamp: TimestampForm,
}

impl EntryForm {
    /// Creates a new entry form with the specified user and path.
    pub fn new(user: UserId, path: Path) -> Self {
        Self {
            auth: AuthForm::Any(user),
            path,
            subspace_id: Default::default(),
            timestamp: Default::default(),
        }
    }
}
