/* ═══════════════════════════════════════════════════════════════════
   media.js — pedidos de filmes e séries pelo Jellyseerr
     !filme <nome>   → busca filmes, você escolhe e confirma
     !serie <nome>   → busca séries, escolhe temporadas e confirma
     !fila           → o que está sendo baixado agora
     !cancelar       → cancela um pedido/download em andamento
     !novidades      → últimos títulos que ficaram disponíveis

   Configuração no .env:
     JELLYSEERR_URL=http://localhost:5055
     JELLYSEERR_KEY=<API Key do Jellyseerr>
     MEDIA_CHANNEL=<ID do canal de pedidos>
   Quem pode usar: quem tem acesso ao MEDIA_CHANNEL (controle pelas permissões do canal).

   Opcional — com as chaves do Radarr/Sonarr, !fila mostra progresso real
   e !cancelar remove o torrent, desmonitora e apaga o pedido:
     RADARR_URL=http://localhost:7878    RADARR_KEY=<API Key>
     SONARR_URL=http://localhost:8989    SONARR_KEY=<API Key>
   ═══════════════════════════════════════════════════════════════════ */
const axios = require("axios");
const {
  ActionRowBuilder,
  StringSelectMenuBuilder,
  ButtonBuilder,
  ButtonStyle,
  ComponentType,
  EmbedBuilder,
  MessageFlags,
} = require("discord.js");

const JS_URL        = (process.env.JELLYSEERR_URL || "http://localhost:5055").replace(/\/+$/, "");
const JS_KEY        = process.env.JELLYSEERR_KEY || "";
const MEDIA_CHANNEL = process.env.MEDIA_CHANNEL || "";

const RADARR = { url: (process.env.RADARR_URL || "http://localhost:7878").replace(/\/+$/, ""), key: process.env.RADARR_KEY || "" };
const SONARR = { url: (process.env.SONARR_URL || "http://localhost:8989").replace(/\/+$/, ""), key: process.env.SONARR_KEY || "" };

const LANG     = "pt-BR";
const ESPERA   = 120000; // 2 minutos para escolher
const MAX_RESULTADOS = 5;

const api = axios.create({
  baseURL: `${JS_URL}/api/v1`,
  headers: { "X-Api-Key": JS_KEY },
  timeout: 20000,
});

const MEDIA_COMMANDS = ["filme", "serie", "série", "fila", "cancelar", "novidades"];

function arrApi(cfg) {
  return axios.create({ baseURL: `${cfg.url}/api/v3`, headers: { "X-Api-Key": cfg.key }, timeout: 20000 });
}
const temArrs = () => Boolean(RADARR.key && SONARR.key);

/* ─── Menus ──────────────────────────────────────────────────────── */
// Menus e botões só aceitam quem mandou o comando. Os outros recebem um aviso só pra eles,
// em vez do "Esta interação falhou" do Discord.
function soDoAutor(message) {
  return (i) => {
    if (i.user.id === message.author.id) return true;
    i.reply({ content: "🔒 Esse menu é de outra pessoa. Mande o seu próprio comando.", flags: MessageFlags.Ephemeral })
      .catch(() => {});
    return false;
  };
}

/* ─── Helpers ────────────────────────────────────────────────────── */
// Status de mídia do Jellyseerr. 1 (desconhecido) e 7 (deletado) ainda podem ser pedidos.
const STATUS_LABEL = {
  2: "⏳ já pedido",
  3: "📥 baixando",
  4: "🟡 parcialmente disponível",
  5: "✅ já está na biblioteca",
  6: "🚫 na blocklist",
};
const podePedirStatus = (status) => status == null || status === 1 || status === 7;

// Status de pedido do Jellyseerr
const PEDIDO_RECUSADO  = 3;
const PEDIDO_CONCLUIDO = 5;

function tituloDe(r)  { return r.title || r.name || r.originalTitle || r.originalName || "Sem título"; }
function anoDe(r)     { return String(r.releaseDate || r.firstAirDate || "").slice(0, 4) || "?"; }
function statusDe(r)  { return STATUS_LABEL[r?.mediaInfo?.status] || null; }

// Mesma regra do servidor do Jellyseerr: uma temporada já existe se está num pedido ativo
// (nem recusado nem concluído) ou se tem qualquer status além de desconhecido/deletado.
function temporadasExistentes(detalhe) {
  const info = detalhe?.mediaInfo;
  if (!info) return [];
  const pedidas = (info.requests || [])
    .filter((p) => !p.is4k && p.status !== PEDIDO_RECUSADO && p.status !== PEDIDO_CONCLUIDO)
    .flatMap((p) => (p.seasons || []).map((s) => s.seasonNumber));
  const naBiblioteca = (info.seasons || [])
    .filter((s) => !podePedirStatus(s.status))
    .map((s) => s.seasonNumber);
  return [...new Set([...pedidas, ...naBiblioteca])].filter((n) => n > 0).sort((a, b) => a - b);
}

function temporadasPediveis(detalhe) {
  const existentes = temporadasExistentes(detalhe);
  return (detalhe.seasons || []).filter((s) => s.seasonNumber > 0 && !existentes.includes(s.seasonNumber));
}

// Busca os títulos em paralelo (antes era um por vez: 20 itens = 20 esperas seguidas)
function nomesDe(itens) {
  return Promise.all(itens.map(async ({ tipo, tmdbId }) => {
    try {
      const d = await detalhes(tipo, tmdbId);
      return `${tituloDe(d)} (${anoDe(d)})`;
    } catch (_) {
      return `TMDB ${tmdbId}`; // segue com o ID
    }
  }));
}

function corta(texto, max) {
  const s = String(texto || "").replace(/\s+/g, " ").trim();
  if (!s) return "";
  return s.length > max ? s.slice(0, max - 1) + "…" : s;
}

function erroApi(error) {
  const status = error.response?.status;
  const msg    = error.response?.data?.message || error.message;
  if (status === 403 || status === 401) return "chave do Jellyseerr inválida";
  if (status === 404) return "não encontrado no Jellyseerr";
  if (error.code === "ECONNREFUSED") return `não consegui falar com o Jellyseerr em ${JS_URL}`;
  return status ? `${status} — ${msg}` : msg;
}

/* ─── Chamadas ao Jellyseerr ─────────────────────────────────────── */
async function buscar(query, tipo) {
  // O Jellyseerr exige a busca totalmente codificada; o axios deixa ':' e ' ' passarem
  const url = `/search?query=${encodeURIComponent(query)}&page=1&language=${LANG}`;
  const { data } = await api.get(url);
  return (data.results || []).filter((r) => r.mediaType === tipo).slice(0, MAX_RESULTADOS);
}

async function detalhes(tipo, tmdbId) {
  const { data } = await api.get(`/${tipo === "movie" ? "movie" : "tv"}/${tmdbId}`, {
    params: { language: LANG },
  });
  return data;
}

async function pedir(tipo, tmdbId, temporadas) {
  const body = { mediaType: tipo, mediaId: Number(tmdbId) };
  if (tipo === "tv") body.seasons = temporadas; // "all" ou [1,2,3]
  const { data } = await api.post("/request", body);
  return data;
}

async function pedidosPorFiltro(filtro) {
  const { data } = await api.get("/request", { params: { filter: filtro, take: 20, sort: "added", skip: 0 } });
  return data.results || [];
}

async function apagarPedido(id) {
  await api.delete(`/request/${id}`);
}

async function ultimosDisponiveis(quantos = 10) {
  const { data } = await api.get("/media", {
    params: { filter: "available", take: quantos, sort: "mediaAdded", skip: 0 },
  });
  return data.results || [];
}

async function processando() {
  const { data } = await api.get("/request", {
    params: { filter: "processing", take: 15, sort: "added", skip: 0 },
  });
  return data.results || [];
}

/* ─── Radarr / Sonarr ────────────────────────────────────────────── */
function tamanho(bytes) {
  const n = Number(bytes || 0);
  if (n >= 1024 ** 3) return `${(n / 1024 ** 3).toFixed(1)} GB`;
  if (n >= 1024 ** 2) return `${(n / 1024 ** 2).toFixed(0)} MB`;
  return `${(n / 1024).toFixed(0)} KB`;
}

function faltaPara(timeleft) {
  if (!timeleft || timeleft === "00:00:00") return null;
  const [h, m] = String(timeleft).split(":");
  const horas = Number(h) || 0, min = Number(m) || 0;
  if (horas >= 24) return `${Math.floor(horas / 24)}d ${horas % 24}h`;
  if (horas > 0) return `${horas}h ${min}min`;
  return `${min}min`;
}

async function filaRadarr() {
  if (!RADARR.key) return [];
  const { data } = await arrApi(RADARR).get("/queue", { params: { pageSize: 100, includeMovie: true } });
  return (data.records || []).map((r) => ({
    origem: "radarr",
    queueId: r.id,
    downloadId: r.downloadId,
    itemId: r.movieId,
    tmdbId: r.movie?.tmdbId,
    titulo: `${r.movie?.title || r.title} (${String(r.movie?.year || "?")})`,
    detalhe: "",
    size: r.size, sizeleft: r.sizeleft, status: r.status, timeleft: r.timeleft,
  }));
}

async function filaSonarr() {
  if (!SONARR.key) return [];
  const { data } = await arrApi(SONARR).get("/queue", {
    params: { pageSize: 100, includeSeries: true, includeEpisode: true },
  });
  return (data.records || []).map((r) => ({
    origem: "sonarr",
    queueId: r.id,
    downloadId: r.downloadId,
    itemId: r.seriesId,
    tvdbId: r.series?.tvdbId,
    seasonNumber: r.episode?.seasonNumber ?? r.seasonNumber,
    episodeId: r.episodeId ?? r.episode?.id,
    titulo: `${r.series?.title || r.title}`,
    detalhe: r.episode ? ` T${r.episode.seasonNumber}E${r.episode.episodeNumber}` : "",
    size: r.size, sizeleft: r.sizeleft, status: r.status, timeleft: r.timeleft,
  }));
}

function agrupar(itens) {
  const mapa = new Map();
  for (const it of itens) {
    const chave = `${it.origem}:${it.downloadId || `q${it.queueId}`}`;
    const g = mapa.get(chave);
    if (!g) {
      mapa.set(chave, { ...it, queueIds: [it.queueId], episodeIds: it.episodeId ? [it.episodeId] : [], episodios: it.detalhe ? 1 : 0, temporadas: new Set(it.seasonNumber != null ? [it.seasonNumber] : []) });
      continue;
    }
    g.queueIds.push(it.queueId);
    if (it.episodeId) g.episodeIds.push(it.episodeId);
    if (it.detalhe) g.episodios += 1;
    if (it.seasonNumber != null) g.temporadas.add(it.seasonNumber);
    // o pacote inteiro tem o mesmo tamanho em todos os registros; fica o menor restante
    if (it.sizeleft < g.sizeleft) { g.sizeleft = it.sizeleft; g.timeleft = it.timeleft; }
  }
  return [...mapa.values()].map((g) => {
    const temps = [...g.temporadas].sort((a, b) => a - b);
    if (g.origem === "sonarr") {
      g.detalhe = g.episodios > 1
        ? ` — T${temps.join(", T")} (${g.episodios} episódios)`
        : g.detalhe;
    }
    return g;
  });
}

async function filaCompleta() {
  const [f, s] = await Promise.all([filaRadarr(), filaSonarr()]);
  return agrupar([...f, ...s]);
}

function linhaFila(it) {
  const pct = it.size ? Math.round(((it.size - it.sizeleft) / it.size) * 100) : 0;
  const falta = faltaPara(it.timeleft);
  const icone = it.origem === "radarr" ? "🎬" : "📺";
  const estado = it.status && it.status !== "downloading" ? ` [${it.status}]` : "";
  return `${icone} **${it.titulo}**${it.detalhe}${estado}\n ${pct}% — ${tamanho(it.size - it.sizeleft)} de ${tamanho(it.size)}${falta ? ` — faltam ${falta}` : ""}`;
}

async function removerDaFila(it) {
  const api = arrApi(it.origem === "radarr" ? RADARR : SONARR);
  const ids = it.queueIds || [it.queueId];
  // o primeiro tira o torrent do qBittorrent; os outros são registros do mesmo pacote
  for (const [pos, id] of ids.entries()) {
    try {
      await api.delete(`/queue/${id}`, { params: { removeFromClient: pos === 0, blocklist: false } });
    } catch (error) {
      if (pos === 0) throw error; // o primeiro é o que importa
    }
  }
  return ids.length;
}

async function desmonitorar(it) {
  const api = arrApi(it.origem === "radarr" ? RADARR : SONARR);
  if (it.origem === "radarr") {
    const { data: filme } = await api.get(`/movie/${it.itemId}`);
    filme.monitored = false;
    await api.put(`/movie/${it.itemId}`, filme);
    return "filme desmonitorado";
  }
  const { data: serie } = await api.get(`/series/${it.itemId}`);
  const alvos = it.temporadas?.size ? [...it.temporadas] : [it.seasonNumber];
  for (const s of serie.seasons || []) if (alvos.includes(s.seasonNumber)) s.monitored = false;
  await api.put(`/series/${it.itemId}`, serie);

  // a temporada sozinha nem sempre basta: os episódios têm monitoramento próprio
  if (it.episodeIds?.length) {
    await api.put("/episode/monitor", { episodeIds: it.episodeIds, monitored: false });
  }
  return `temporada${alvos.length > 1 ? "s" : ""} ${alvos.join(", ")} desmonitorada${alvos.length > 1 ? "s" : ""}`;
}

async function removerDoCatalogo(it) {
  const api = arrApi(it.origem === "radarr" ? RADARR : SONARR);
  const rota = it.origem === "radarr" ? `/movie/${it.itemId}` : `/series/${it.itemId}`;
  await api.delete(rota, { params: { deleteFiles: false, addImportListExclusion: false } });
  return it.origem === "radarr" ? "filme removido do Radarr" : "série removida do Sonarr";
}

// Apaga no Jellyseerr os pedidos do que foi cancelado. Um pedido de série que também cobre
// outras temporadas fica: apagá-lo tiraria do Jellyseerr temporadas que seguem baixando.
async function apagarPedidoDe(it) {
  const { data } = await api.get("/request", { params: { take: 50, filter: "all", sort: "added", skip: 0 } });
  const canceladas = it.temporadas?.size ? [...it.temporadas] : [it.seasonNumber];
  const doTitulo = (data.results || []).filter((p) =>
    it.origem === "radarr"
      // o tipo importa: filme e série podem ter o mesmo número de ID no TMDB
      ? p.type === "movie" && p.media?.tmdbId === it.tmdbId
      : p.type === "tv" && p.media?.tvdbId === it.tvdbId &&
        (p.seasons || []).some((s) => canceladas.includes(s.seasonNumber))
  );

  let apagados = 0, mantidos = 0;
  for (const p of doTitulo) {
    const temOutras = it.origem === "sonarr" && (p.seasons || []).some((s) => !canceladas.includes(s.seasonNumber));
    if (temOutras) { mantidos += 1; continue; }
    await apagarPedido(p.id);
    apagados += 1;
  }
  return { apagados, mantidos };
}

/* ─── Blocos visuais ─────────────────────────────────────────────── */
function menuResultados(resultados) {
  const menu = new StringSelectMenuBuilder()
    .setCustomId("escolha")
    .setPlaceholder("Escolha o título certo")
    .addOptions(
      resultados.map((r) => {
        const marca = statusDe(r);
        return {
          label: corta(`${tituloDe(r)} (${anoDe(r)})`, 100),
          description: corta(marca ? `${marca} — ${r.overview || ""}` : r.overview || "Sem sinopse", 100),
          value: String(r.id),
        };
      })
    );
  return new ActionRowBuilder().addComponents(menu);
}

// Recebe só as temporadas que ainda dá pra pedir. `parcial` = a série já tem outras.
function menuTemporadas(pediveis, parcial = false) {
  const temporadas = pediveis.slice(0, 24);
  const menu = new StringSelectMenuBuilder()
    .setCustomId("temporadas")
    .setPlaceholder("Quais temporadas?")
    .setMinValues(1)
    .setMaxValues(temporadas.length + 1)
    .addOptions([
      { label: parcial ? "Todas as que faltam" : "Todas as temporadas", value: "all", description: `${pediveis.length} temporada(s)` },
      ...temporadas.map((s) => ({
        label: corta(`Temporada ${s.seasonNumber}`, 100),
        description: corta(`${s.episodeCount || "?"} episódios${s.airDate ? ` — ${String(s.airDate).slice(0, 4)}` : ""}`, 100),
        value: String(s.seasonNumber),
      })),
    ]);
  return new ActionRowBuilder().addComponents(menu);
}

function botoes(habilitado = true) {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId("confirmar").setLabel("Pedir").setEmoji("✅").setStyle(ButtonStyle.Success).setDisabled(!habilitado),
    new ButtonBuilder().setCustomId("cancelar").setLabel("Cancelar").setEmoji("❌").setStyle(ButtonStyle.Secondary).setDisabled(!habilitado)
  );
}

function embedDetalhe(detalhe, tipo, extra) {
  const nota = detalhe.voteAverage ? `⭐ ${Number(detalhe.voteAverage).toFixed(1)}` : null;
  const dur  = detalhe.runtime ? `⏱️ ${detalhe.runtime} min` : null;
  const temps = detalhe.numberOfSeasons ? `📺 ${detalhe.numberOfSeasons} temporada(s)` : null;
  const linha = [anoDe(detalhe), nota, dur, temps].filter(Boolean).join("  •  ");

  const embed = new EmbedBuilder()
    .setTitle(corta(`${tituloDe(detalhe)} (${anoDe(detalhe)})`, 256))
    .setDescription(corta(detalhe.overview || "Sem sinopse em português.", 600))
    .setColor(tipo === "movie" ? 0x5865f2 : 0xeb459e)
    .addFields({ name: "​", value: linha || "​" });

  if (detalhe.posterPath) embed.setThumbnail(`https://image.tmdb.org/t/p/w342${detalhe.posterPath}`);
  if (extra) embed.addFields({ name: "Situação", value: extra });
  return embed;
}

/* ─── Comando !fila ──────────────────────────────────────────────── */
async function comandoFila(message) {
  const aviso = await message.reply("⏳ Consultando a fila...");
  try {
    if (temArrs()) {
      const itens = await filaCompleta();
      if (!itens.length) return aviso.edit("✅ Nada sendo baixado no momento.");
      const linhas = itens.slice(0, 12).map(linhaFila);
      const extra = itens.length > 12 ? `\n\n_(+${itens.length - 12} item(ns))_` : "";
      return aviso.edit(`📥 **Baixando agora (${itens.length})**\n\n${linhas.join("\n")}${extra}`);
    }

    // sem as chaves do Radarr/Sonarr: mostra só os títulos, pelo Jellyseerr
    const pedidos = await processando();
    if (!pedidos.length) return aviso.edit("✅ Nada sendo baixado no momento.");
    const lista = pedidos.slice(0, 10);
    const nomes = await nomesDe(lista.map((p) => ({ tipo: p.type === "tv" ? "tv" : "movie", tmdbId: p.media?.tmdbId })));
    const linhas = lista.map((p, i) => {
      const temps = p.seasons?.length ? ` — temporada(s) ${p.seasons.map((s) => s.seasonNumber).join(", ")}` : "";
      return `${p.type === "tv" ? "📺" : "🎬"} **${nomes[i]}**${temps}`;
    });
    await aviso.edit(`📥 **Baixando agora (${pedidos.length})**\n\n${linhas.join("\n")}`);
  } catch (error) {
    console.error("[!fila] Error:", error.message);
    await aviso.edit(`❌ Erro ao consultar a fila: ${erroApi(error)}`);
  }
}

/* ─── Comando !novidades ─────────────────────────────────────────── */
async function comandoNovidades(message) {
  const aviso = await message.reply("⏳ Buscando os últimos títulos...");
  try {
    const itens = await ultimosDisponiveis(10);
    if (!itens.length) return aviso.edit("🤷 Nada marcado como disponível ainda.");

    const nomes = await nomesDe(itens.map((m) => ({ tipo: m.mediaType === "tv" ? "tv" : "movie", tmdbId: m.tmdbId })));
    const linhas = itens.map((m, i) => {
      const quando = m.mediaAddedAt ? ` — ${new Date(m.mediaAddedAt).toLocaleDateString("pt-BR")}` : "";
      return `${m.mediaType === "tv" ? "📺" : "🎬"} **${nomes[i]}**${quando}`;
    });
    await aviso.edit(`✅ **Últimos títulos disponíveis**\n\n${linhas.join("\n")}`);
  } catch (error) {
    console.error("[!novidades] Error:", error.message);
    await aviso.edit(`❌ Erro ao consultar: ${erroApi(error)}`);
  }
}

/* ─── Comando !cancelar ──────────────────────────────────────────── */
async function comandoCancelar(message) {
  const aviso = await message.reply("⏳ Listando o que dá pra cancelar...");

  /* Sem as chaves do Radarr/Sonarr: só apaga o pedido no Jellyseerr */
  if (!temArrs()) {
    let pedidos;
    try {
      const [pendentes, baixando] = await Promise.all([
        pedidosPorFiltro("pending"),
        pedidosPorFiltro("processing"),
      ]);
      pedidos = [...pendentes, ...baixando].slice(0, 20);
    } catch (error) {
      console.error("[!cancelar] Lista:", error.message);
      return aviso.edit(`❌ Erro ao listar: ${erroApi(error)}`);
    }
    if (!pedidos.length) return aviso.edit("✅ Não há pedido em aberto pra cancelar.");

    const nomes = await nomesDe(pedidos.map((p) => ({ tipo: p.type === "tv" ? "tv" : "movie", tmdbId: p.media?.tmdbId })));
    const opcoes = pedidos.map((p, i) => ({
      label: corta(`${p.type === "tv" ? "📺" : "🎬"} ${nomes[i]}`, 100),
      value: String(p.id),
    }));
    const menu = new ActionRowBuilder().addComponents(
      new StringSelectMenuBuilder().setCustomId("cancelar").setPlaceholder("Qual pedido cancelar?").addOptions(opcoes)
    );
    await aviso.edit({ content: `🗑️ **${opcoes.length} pedido(s) em aberto**:`, components: [menu] });

    let escolha;
    try {
      escolha = await aviso.awaitMessageComponent({
        filter: soDoAutor(message),
        componentType: ComponentType.StringSelect,
        time: ESPERA,
      });
    } catch (_) {
      return aviso.edit({ content: "⌛ Tempo esgotado. Mande o comando de novo.", components: [] });
    }
    await escolha.deferUpdate();
    try {
      await apagarPedido(escolha.values[0]);
      return aviso.edit({
        content: "🗑️ Pedido apagado no Jellyseerr.\n⚠️ Se já estava baixando, o download segue no qBittorrent.",
        components: [],
      });
    } catch (error) {
      return aviso.edit({ content: `❌ Não consegui cancelar: ${erroApi(error)}`, components: [] });
    }
  }

  /* Com as chaves: cancela de verdade (fila + torrent + monitoramento + pedido) */
  let itens;
  try {
    itens = await filaCompleta();
  } catch (error) {
    console.error("[!cancelar] Fila:", error.message);
    return aviso.edit(`❌ Erro ao consultar Radarr/Sonarr: ${erroApi(error)}`);
  }
  if (!itens.length) return aviso.edit("✅ Não há download em andamento pra cancelar.");

  const opcoes = itens.slice(0, 25).map((it, idx) => {
    const pct = it.size ? Math.round(((it.size - it.sizeleft) / it.size) * 100) : 0;
    return {
      label: corta(`${it.origem === "radarr" ? "🎬" : "📺"} ${it.titulo}${it.detalhe}`, 100),
      description: corta(`${pct}% — ${tamanho(it.size)}`, 100),
      value: String(idx),
    };
  });

  const menu = new ActionRowBuilder().addComponents(
    new StringSelectMenuBuilder()
      .setCustomId("cancelar")
      .setPlaceholder("Quais downloads cancelar?")
      .setMinValues(1)
      .setMaxValues(opcoes.length)
      .addOptions(opcoes)
  );
  await aviso.edit({
    content: `🗑️ **${itens.length} download(s) em andamento** — pode marcar mais de um e clicar fora do menu pra confirmar:`,
    components: [menu],
  });

  let escolha;
  try {
    escolha = await aviso.awaitMessageComponent({
      filter: soDoAutor(message),
      componentType: ComponentType.StringSelect,
      time: ESPERA,
    });
  } catch (_) {
    return aviso.edit({ content: "⌛ Tempo esgotado. Mande o comando de novo.", components: [] });
  }
  await escolha.deferUpdate();

  const alvos = escolha.values.map((v) => itens[Number(v)]);
  const passos = [];

  for (const alvo of alvos) {
    passos.push(`**${alvo.titulo}${alvo.detalhe}**`);

    try {
      await removerDaFila(alvo);
      passos.push("✅ removido da fila e do qBittorrent");
    } catch (error) {
      console.error("[!cancelar] Fila:", error.message);
      passos.push(`❌ fila: ${erroApi(error)}`);
    }

    try {
      passos.push(`✅ ${await desmonitorar(alvo)}`);
    } catch (error) {
      console.error("[!cancelar] Monitoramento:", error.message);
      passos.push(`❌ monitoramento: ${erroApi(error)}`);
    }

    try {
      const { apagados, mantidos } = await apagarPedidoDe(alvo);
      if (apagados) passos.push("✅ pedido apagado no Jellyseerr");
      if (mantidos) passos.push("ℹ️ pedido mantido no Jellyseerr (ele cobre outras temporadas)");
      if (!apagados && !mantidos) passos.push("ℹ️ não havia pedido no Jellyseerr");
    } catch (error) {
      console.error("[!cancelar] Jellyseerr:", error.message);
      passos.push(`❌ Jellyseerr: ${erroApi(error)}`);
    }
  }

  const alvo = alvos[0];

  const mesmoTitulo = alvos.every((a) => a.origem === alvo.origem && a.itemId === alvo.itemId);
  if (!mesmoTitulo) {
    return aviso.edit({ content: `🗑️ ${passos.join("\n")}`, components: [] });
  }

  const botaoRemover = new ActionRowBuilder().addComponents(
    new ButtonBuilder()
      .setCustomId("remover")
      .setLabel(alvo.origem === "radarr" ? "Remover do Radarr também" : "Remover do Sonarr também")
      .setEmoji("🧹")
      .setStyle(ButtonStyle.Danger)
  );

  await aviso.edit({
    content: `🗑️ ${passos.join("\n")}\n\nO cadastro continua lá, só desmonitorado. Quer tirar da lista também? (os arquivos já baixados não são apagados)`,
    components: [botaoRemover],
  });

  let clique;
  try {
    clique = await aviso.awaitMessageComponent({
      filter: soDoAutor(message),
      componentType: ComponentType.Button,
      time: ESPERA,
    });
  } catch (_) {
    return aviso.edit({ content: `🗑️ ${passos.join("\n")}`, components: [] });
  }
  await clique.deferUpdate();

  try {
    // nada pode continuar baixando: sem o cadastro, o torrent fica órfão no qBittorrent
    const restantes = (await filaCompleta()).filter(
      (g) => g.origem === alvo.origem && g.itemId === alvo.itemId
    );
    for (const g of restantes) {
      await removerDaFila(g);
      passos.push(`✅ também cancelei ${g.titulo}${g.detalhe}`);
    }
    passos.push(`✅ ${await removerDoCatalogo(alvo)}`);
  } catch (error) {
    console.error("[!cancelar] Catálogo:", error.message);
    passos.push(`❌ catálogo: ${erroApi(error)}`);
  }
  await aviso.edit({ content: `🗑️ ${passos.join("\n")}`, components: [] });
}

/* ─── Comandos !filme e !serie ───────────────────────────────────── */
async function comandoBusca(message, tipo, termo) {
  const aviso = await message.reply(`🔎 Procurando \`${termo}\`...`);

  let resultados;
  try {
    resultados = await buscar(termo, tipo);
  } catch (error) {
    console.error("[!media] Busca:", error.message);
    return aviso.edit(`❌ Erro na busca: ${erroApi(error)}`);
  }

  if (!resultados.length) {
    return aviso.edit(`🤷 Nenhum ${tipo === "movie" ? "filme" : "série"} encontrado para \`${termo}\`.`);
  }

  await aviso.edit({
    content: `🔎 **${resultados.length} resultado(s)** para \`${termo}\` — escolha o certo:`,
    components: [menuResultados(resultados)],
  });

  /* 1) escolha do título */
  let escolha;
  try {
    escolha = await aviso.awaitMessageComponent({
      filter: soDoAutor(message),
      componentType: ComponentType.StringSelect,
      time: ESPERA,
    });
  } catch (_) {
    return aviso.edit({ content: "⌛ Tempo esgotado. Mande o comando de novo.", components: [] });
  }
  await escolha.deferUpdate();

  const tmdbId = escolha.values[0];
  let detalhe;
  try {
    detalhe = await detalhes(tipo, tmdbId);
  } catch (error) {
    console.error("[!media] Detalhes:", error.message);
    return aviso.edit({ content: `❌ Erro ao buscar detalhes: ${erroApi(error)}`, components: [] });
  }

  const situacao = statusDe(detalhe);

  // Série parcialmente disponível ainda aceita as temporadas que faltam;
  // só bloqueia quando não sobrou nenhuma. Filme bloqueia se já existe.
  const existentes = tipo === "tv" ? temporadasExistentes(detalhe) : [];
  const pediveis   = tipo === "tv" ? temporadasPediveis(detalhe) : [];

  if (tipo === "tv" && !pediveis.length && !existentes.length) {
    return aviso.edit({
      content: "🤷 O TMDB ainda não tem temporadas cadastradas pra essa série.",
      embeds: [embedDetalhe(detalhe, tipo)],
      components: [],
    });
  }
  if (tipo === "tv" ? !pediveis.length : !podePedirStatus(detalhe?.mediaInfo?.status)) {
    const rotulo = situacao || STATUS_LABEL[2];
    return aviso.edit({
      content: `ℹ️ Esse título já está na sua lista: **${rotulo}**.`,
      embeds: [embedDetalhe(detalhe, tipo, rotulo)],
      components: [],
    });
  }

  /* 2) temporadas (só séries) */
  let temporadas = "all";
  const parcial = existentes.length > 0;
  if (tipo === "tv") {
    const jaTem = parcial ? `🟡 Já tem ou já pediu: T${existentes.join(", T")}` : undefined;
    await aviso.edit({
      content: parcial ? "📺 Quais das temporadas que faltam você quer?" : "📺 Quais temporadas você quer?",
      embeds: [embedDetalhe(detalhe, tipo, jaTem)],
      components: [menuTemporadas(pediveis, parcial)],
    });

    let escolhaTemp;
    try {
      escolhaTemp = await aviso.awaitMessageComponent({
        filter: soDoAutor(message),
        componentType: ComponentType.StringSelect,
        time: ESPERA,
      });
    } catch (_) {
      return aviso.edit({ content: "⌛ Tempo esgotado. Mande o comando de novo.", embeds: [], components: [] });
    }
    await escolhaTemp.deferUpdate();
    temporadas = escolhaTemp.values.includes("all") ? "all" : escolhaTemp.values.map(Number);
  }

  /* 3) confirmação */
  const resumo = tipo === "tv"
    // "all" com série parcial: o Jellyseerr pede só as que faltam (ele mesmo descarta as existentes)
    ? `Temporadas: **${temporadas === "all" ? (parcial ? "todas as que faltam" : "todas") : temporadas.join(", ")}**`
    : "Filme completo";

  await aviso.edit({
    content: `Confirma o pedido? ${resumo}`,
    embeds: [embedDetalhe(detalhe, tipo)],
    components: [botoes()],
  });

  let clique;
  try {
    clique = await aviso.awaitMessageComponent({
      filter: soDoAutor(message),
      componentType: ComponentType.Button,
      time: ESPERA,
    });
  } catch (_) {
    return aviso.edit({ content: "⌛ Tempo esgotado. Mande o comando de novo.", embeds: [], components: [] });
  }
  await clique.deferUpdate();

  if (clique.customId === "cancelar") {
    return aviso.edit({ content: "❌ Pedido cancelado.", embeds: [], components: [] });
  }

  /* 4) manda pro Jellyseerr */
  try {
    await pedir(tipo, tmdbId, temporadas);
    await aviso.edit({
      content: `📥 **Pedido enviado** — ${tituloDe(detalhe)} (${anoDe(detalhe)})\n${resumo}\nAviso aqui quando estiver disponível.`,
      embeds: [embedDetalhe(detalhe, tipo)],
      components: [],
    });
  } catch (error) {
    console.error("[!media] Pedido:", error.message);
    await aviso.edit({ content: `❌ Não consegui fazer o pedido: ${erroApi(error)}`, embeds: [], components: [] });
  }
}

/* ─── Entrada ────────────────────────────────────────────────────── */
async function handleMediaCommand(message, command, args) {
  if (MEDIA_CHANNEL && message.channel.id !== MEDIA_CHANNEL) return;
  if (!JS_KEY) return message.reply("⚠️ Falta a `JELLYSEERR_KEY` no `.env` do bot.");

  if (command === "fila") return comandoFila(message);
  if (command === "novidades") return comandoNovidades(message);
  if (command === "cancelar") return comandoCancelar(message);

  const termo = args.join(" ").trim();
  const tipo  = command === "filme" ? "movie" : "tv";
  if (!termo) {
    return message.reply(`⚠️ Use: \`!${command} nome\` — Ex: \`!${command} ${tipo === "movie" ? "duna" : "breaking bad"}\``);
  }
  return comandoBusca(message, tipo, termo);
}

module.exports = {
  MEDIA_COMMANDS,
  handleMediaCommand,
  // exportados para teste
  _internals: { buscar, detalhes, pedir, processando, pedidosPorFiltro, apagarPedido, ultimosDisponiveis, corta, tituloDe, anoDe, JS_URL,
                filaRadarr, filaSonarr, filaCompleta, agrupar, linhaFila, removerDaFila, desmonitorar, removerDoCatalogo, apagarPedidoDe, tamanho,
                menuResultados, menuTemporadas, botoes, embedDetalhe,
                temporadasExistentes, temporadasPediveis, podePedirStatus, nomesDe, soDoAutor },
};
