const axios = require('axios');
const cheerio = require('cheerio');
const fs = require('fs');
const path = require('path');

const BASE_URL = 'https://coinvertify.com';
const IMG_DIR = path.join(__dirname, '..', 'img', 'gifts');
const CATALOG_PATH = path.join(__dirname, '..', 'public', 'gifts-catalog.json');

function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function getListeCadeaux() {
  const { data: html } = await axios.get(`${BASE_URL}/fr/tiktok-gifts?page=1`);
  const $ = cheerio.load(html);
  const cadeaux = new Map();

  $('a').each((i, element) => {
    const href = $(element).attr('href');
    const texte = $(element).text().trim();

    if (!href) return;
    if (!href.startsWith('/fr/tiktok-gifts/')) return;
    if (href.includes('?')) return;

    const slug = href.split('/').pop();
    cadeaux.set(slug, { name: texte, slug });
  });

  return [...cadeaux.values()];
}

async function getDetailsCadeau(slug) {
  const url = `${BASE_URL}/fr/tiktok-gifts/${slug}`;
  const { data: html } = await axios.get(url);
  const $ = cheerio.load(html);

  // On utilise le sélecteur cheerio plutôt qu'une regex sur le HTML brut :
  // beaucoup plus fiable (peu importe l'espacement ou l'ordre des attributs).
  const imageUrl = $('meta[property="og:image"]').attr('content') || null;

  // Pour le prix, on récupère TOUT le texte visible de la page (sans les balises),
  // ce qui évite les faux négatifs à cause de balises entre les mots.
  const texteComplet = $('body').text().replace(/\s+/g, ' ');
  const matchPrix = texteComplet.match(/vaut\s+(\d+)\s+pi[eè]ces/i);
  const prix = matchPrix ? parseInt(matchPrix[1], 10) : null;

  return { imageUrl, prix, htmlBrut: html };
}

async function telechargerImage(imageUrl, slug) {
  const extension = path.extname(new URL(imageUrl).pathname) || '.webp';
  const nomFichier = `${slug}${extension}`;
  const cheminFichier = path.join(IMG_DIR, nomFichier);

  const reponse = await axios.get(imageUrl, { responseType: 'arraybuffer' });
  fs.writeFileSync(cheminFichier, reponse.data);

  return `/img/gifts/${nomFichier}`;
}

async function main() {
  if (!fs.existsSync(IMG_DIR)) fs.mkdirSync(IMG_DIR, { recursive: true });

  console.log('Récupération de la liste des cadeaux...');
  const liste = await getListeCadeaux();
  console.log(liste.length, 'cadeaux trouvés.');

  const catalogue = [];
  let debugSauvegarde = false;

  for (let i = 0; i < liste.length; i++) {
    const { name, slug } = liste[i];
    try {
      const { imageUrl, prix, htmlBrut } = await getDetailsCadeau(slug);

      if (!imageUrl || !prix) {
        console.log(`⚠️  ${name} (${slug}) : image=${imageUrl} prix=${prix}`);

        // Dès le premier échec, on sauvegarde le HTML brut de la page pour l'inspecter.
        if (!debugSauvegarde) {
          fs.writeFileSync(path.join(__dirname, 'debug-page.html'), htmlBrut);
          console.log(`   -> HTML brut sauvegardé dans scripts/debug-page.html pour inspection`);
          debugSauvegarde = true;
        }
        continue;
      }

      const cheminImage = await telechargerImage(imageUrl, slug);

      catalogue.push({
        name,
        diamond_count: prix,
        image: cheminImage
      });

      console.log(`✅ (${i + 1}/${liste.length}) ${name} - ${prix} pièces`);
    } catch (err) {
      console.log(`❌ Erreur sur ${name} (${slug}) :`, err.message);
    }

    await delay(400);
  }

  catalogue.sort((a, b) => a.diamond_count - b.diamond_count);
  fs.writeFileSync(CATALOG_PATH, JSON.stringify(catalogue, null, 2));

  console.log(`\n🎉 Terminé ! ${catalogue.length} cadeaux enregistrés dans ${CATALOG_PATH}`);
}

main();