// pptx-preview.js — renders .pptx slides as positioned HTML boxes.
// Parses slide XML (text boxes, placeholders, pictures) and resolves
// layout/master style chains (fonts, colors, alignment, bullets) entirely
// in the browser. No server involvement.
(function () {
  'use strict';

  var SCHEME_COLORS = {
    tx1: '#000000', tx2: '#44546A', bg1: '#FFFFFF', bg2: '#FFFFFF',
    dk1: '#000000', dk2: '#44546A', lt1: '#FFFFFF', lt2: '#D6DCE4',
    accent1: '#4472C4', accent2: '#ED7D31', accent3: '#A5A5A5',
    accent4: '#FFC000', accent5: '#5B9BD5', accent6: '#70AD47',
    hlink: '#0563C1', folHlink: '#954F72'
  };

  function parseXml(xml) {
    return new DOMParser().parseFromString(xml, 'application/xml');
  }

  function escapeHtml(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function readXfrm(xfrm) {
    if (!xfrm) return null;
    var off = xfrm.getElementsByTagName('a:off')[0];
    var ext = xfrm.getElementsByTagName('a:ext')[0];
    if (!off || !ext) return null;
    var cx = parseFloat(ext.getAttribute('cx')) || 0;
    var cy = parseFloat(ext.getAttribute('cy')) || 0;
    if (cx <= 0 || cy <= 0) return null;
    return {
      x: parseFloat(off.getAttribute('x')) || 0,
      y: parseFloat(off.getAttribute('y')) || 0,
      cx: cx,
      cy: cy
    };
  }

  function pptxColorOf(el) {
    if (!el) return null;
    var solid = el.getElementsByTagName('a:solidFill')[0];
    if (!solid) return null;
    var srgb = solid.getElementsByTagName('a:srgbClr')[0];
    if (srgb) return '#' + srgb.getAttribute('val');
    var sch = solid.getElementsByTagName('a:schemeClr')[0];
    if (sch) return SCHEME_COLORS[sch.getAttribute('val')] || '#000000';
    return null;
  }

  // Parse one <a:lvlNpPr> element into a plain style object.
  function parseLevelStyle(el) {
    var st = { sz: null, bold: null, italic: null, color: null, algn: null, marL: null, bullet: null };
    if (!el) return st;
    st.algn = el.getAttribute('algn') || null;
    st.marL = el.getAttribute('marL') ? parseFloat(el.getAttribute('marL')) : null;
    var def = el.getElementsByTagName('a:defRPr')[0];
    if (def) {
      st.sz = def.getAttribute('sz') ? parseFloat(def.getAttribute('sz')) : null;
      st.bold = def.getAttribute('b') === '1';
      st.italic = def.getAttribute('i') === '1';
      st.color = pptxColorOf(def);
    }
    if (el.getElementsByTagName('a:buNone').length) st.bullet = 'none';
    var bc = el.getElementsByTagName('a:buChar')[0];
    if (bc) st.bullet = bc.getAttribute('char') || '\u2022';
    if (el.getElementsByTagName('a:buAutoNum').length) st.bullet = 'num';
    return st;
  }

  // Extract per-level styles from a style container subtree.
  function parseStyleSet(xml, containerName) {
    var out = {};
    var sub = xml;
    if (containerName) {
      var re = new RegExp('<' + containerName + '>[\\s\\S]*?<\\/' + containerName + '>');
      var m = xml.match(re);
      if (!m) return out;
      sub = m[0];
    }
    var doc = parseXml(sub);
    for (var i = 1; i <= 9; i++) {
      var el = doc.getElementsByTagName('a:lvl' + i + 'pPr')[0];
      if (el) out['lvl' + i] = parseLevelStyle(el);
    }
    return out;
  }

  // Merge base, then over — only non-null fields of `over` win.
  function mergeStyle(base, over) {
    var out = {};
    for (var k in base) out[k] = base[k];
    if (over) {
      for (var k2 in over) {
        if (over[k2] !== null && over[k2] !== undefined) out[k2] = over[k2];
      }
    }
    return out;
  }

  function parseRels(relsXml) {
    var rels = {};
    var re = /<Relationship\s+Id="([^"]+)"[^>]*Target="([^"]+)"/g;
    var m;
    while ((m = re.exec(relsXml))) rels[m[1]] = m[2];
    return rels;
  }

  // EMU -> px for a slide rendered at scale `pxPerEmu` (px per EMU).
  function fontPx(szHundredthsPt, pxPerEmu) {
    var pt = (szHundredthsPt || 1800) / 100;
    return (pt * pxPerEmu * 914400) / 72;
  }

  // Fallback boxes (fractions of slide size) when layout has no usable box.
  function defaultPhBox(phType) {
    if (phType === 'title' || phType === 'ctrTitle') return { x: 0.05, y: 0.035, cx: 0.9, cy: 0.13 };
    if (phType === 'subTitle') return { x: 0.07, y: 0.2, cx: 0.86, cy: 0.14 };
    return { x: 0.05, y: 0.18, cx: 0.9, cy: 0.75 };
  }

  // ── Load every layout + master: placeholder boxes, level styles, and
  //    layout -> master mapping (via slideLayoutN.xml.rels). ──
  function loadTheme(zip) {
    var layoutFiles = Object.keys(zip.files).filter(function (n) {
      return /^ppt\/slideLayouts\/slideLayout\d+\.xml$/.test(n);
    });
    var masterFiles = Object.keys(zip.files).filter(function (n) {
      return /^ppt\/slideMasters\/slideMaster\d+\.xml$/.test(n);
    });
    return Promise.all(layoutFiles.concat(masterFiles).map(function (n) {
      return zip.files[n].async('text').then(function (xml) {
        var isLayout = n.indexOf('/slideLayouts/') !== -1;
        var key = n.split('/').pop().replace(/\.xml$/, '');
        var doc = parseXml(xml);
        var phs = [];
        var sps = doc.getElementsByTagName('p:sp');
        for (var i = 0; i < sps.length; i++) {
          var ph = sps[i].getElementsByTagName('p:ph')[0];
          if (!ph) continue;
          phs.push({
            type: ph.getAttribute('type') || 'obj',
            idx: ph.getAttribute('idx'),
            box: readXfrm(sps[i].getElementsByTagName('a:xfrm')[0])
          });
        }
        return {
          key: key,
          isLayout: isLayout,
          phs: phs,
          xml: xml,
          titleLevels: parseStyleSet(xml, 'p:titleStyle'),
          bodyLevels: parseStyleSet(xml, 'p:bodyStyle')
        };
      });
    })).then(function (entries) {
      var theme = { layouts: {}, masters: {} };
      entries.forEach(function (e) {
        if (e.isLayout) theme.layouts[e.key] = e;
        else theme.masters[e.key] = e;
      });
      var relsRe = /slideMasters\/slideMaster(\d+)\.xml/;
      return Promise.all(layoutFiles.map(function (n) {
        var rels = zip.file('ppt/slideLayouts/_rels/' + n.split('/').pop() + '.rels');
        if (!rels) return null;
        return rels.async('text').then(function (txt) {
          var m = txt.match(relsRe);
          return {
            layoutKey: n.split('/').pop().replace(/\.xml$/, ''),
            masterKey: m ? 'slideMaster' + m[1] : null
          };
        });
      })).then(function (map) {
        map.forEach(function (pair) {
          if (pair) theme.layouts[pair.layoutKey].masterKey = pair.masterKey;
        });
        return theme;
      });
    });
  }

  // Merge defaultTextStyle -> master levels -> layout levels (layout wins).
  function chainLevels(defaultStyle, layout, master) {
    var merged = {};
    for (var i = 1; i <= 9; i++) {
      var key = 'lvl' + i;
      var st = mergeStyle(defaultStyle[key] || {}, master ? master[key] || {} : {});
      st = mergeStyle(st, layout ? layout[key] || {} : {});
      merged[key] = st;
    }
    return merged;
  }

  // ── Render one slide ──
  function renderSlide(slideXml, relsXml, zip, slideW, slideH, num, theme, defaultStyle) {
    var doc = parseXml(slideXml);
    var rels = parseRels(relsXml);
    var layoutKey = null;
    for (var rId in rels) {
      if (rels[rId].indexOf('slideLayouts/') !== -1) {
        layoutKey = rels[rId].split('/').pop().replace(/\.xml$/, '');
        break;
      }
    }
    var layout = theme.layouts[layoutKey] || null;
    var master = layout && layout.masterKey ? theme.masters[layout.masterKey] : null;

    var S = 760;
    var pxPerEmu = S / slideW;
    var mediaCache = {};

    function mediaUrl(rId) {
      if (mediaCache[rId] !== undefined) return Promise.resolve(mediaCache[rId]);
      mediaCache[rId] = null;
      if (!rels[rId]) return Promise.resolve(null);
      var path = 'ppt/' + rels[rId].replace(/^\.\.\//, '');
      var f = zip.file(path);
      if (!f) return Promise.resolve(null);
      return f.async('base64').then(function (b64) {
        var ext = path.split('.').pop().toLowerCase();
        var mime = { png: 'image/png', jpg: 'image/jpeg', jpeg: 'image/jpeg', gif: 'image/gif', svg: 'image/svg+xml', bmp: 'image/bmp' }[ext] || 'image/' + ext;
        mediaCache[rId] = 'data:' + mime + ';base64,' + b64;
        return mediaCache[rId];
      });
    }

    function resolvePhBox(phType, phIdx) {
      if (layout) {
        for (var i = 0; i < layout.phs.length; i++) {
          var p = layout.phs[i];
          if (p.box && p.type === phType && (phIdx === null || phIdx === undefined || p.idx === phIdx || p.idx === null)) return p.box;
        }
        for (var j = 0; j < layout.phs.length; j++) {
          var p2 = layout.phs[j];
          if (p2.box && p2.type === phType) return p2.box;
        }
        if (phIdx !== null && phIdx !== undefined) {
          for (var k = 0; k < layout.phs.length; k++) {
            var p3 = layout.phs[k];
            if (p3.box && p3.idx === phIdx) return p3.box;
          }
        }
      }
      var def = defaultPhBox(phType);
      return { x: def.x * slideW, y: def.y * slideH, cx: def.cx * slideW, cy: def.cy * slideH };
    }

    function shapeKind(phType) {
      return (phType === 'title' || phType === 'ctrTitle') ? 'title' : 'body';
    }

    function renderParagraph(p, levels, pxPerEmu, nextNum) {
      var pPr = p.getElementsByTagName('a:pPr')[0];
      var lvl = 0;
      if (pPr && pPr.getAttribute('lvl')) lvl = parseInt(pPr.getAttribute('lvl'), 10);
      var key = 'lvl' + Math.min(9, lvl + 1);
      var st = mergeStyle(levels[key] || {});
      if (pPr) {
        if (pPr.getAttribute('algn')) st.algn = pPr.getAttribute('algn');
        if (pPr.getAttribute('marL')) st.marL = parseFloat(pPr.getAttribute('marL'));
        if (pPr.getElementsByTagName('a:buChar').length) {
          st.bullet = pPr.getElementsByTagName('a:buChar')[0].getAttribute('char') || '\u2022';
        } else if (pPr.getElementsByTagName('a:buAutoNum').length) {
          st.bullet = 'num';
        } else if (pPr.getElementsByTagName('a:buNone').length) {
          st.bullet = 'none';
        }
        var def = pPr.getElementsByTagName('a:defRPr')[0];
        if (def) {
          if (def.getAttribute('sz')) st.sz = parseFloat(def.getAttribute('sz'));
          if (def.getAttribute('b') === '1') st.bold = true;
          if (def.getAttribute('i') === '1') st.italic = true;
          var c = pptxColorOf(def);
          if (c) st.color = c;
        }
      }
      var runs = p.getElementsByTagName('a:r');
      var inner = '';
      var anyText = false;
      for (var i = 0; i < runs.length; i++) {
        var r = runs[i];
        var rPr = r.getElementsByTagName('a:rPr')[0];
        var sz = st.sz;
        var bold = st.bold;
        var italic = st.italic;
        var color = st.color;
        if (rPr) {
          if (rPr.getAttribute('sz')) sz = parseFloat(rPr.getAttribute('sz'));
          if (rPr.getAttribute('b') === '1') bold = true;
          if (rPr.getAttribute('i') === '1') italic = true;
          var rc = pptxColorOf(rPr);
          if (rc) color = rc;
        }
        var t = r.getElementsByTagName('a:t')[0];
        var text = t ? t.textContent : '';
        if (!text) continue;
        anyText = true;
        var rs = 'font-size:' + fontPx(sz, pxPerEmu) + 'px;';
        if (bold) rs += 'font-weight:700;';
        if (italic) rs += 'font-style:italic;';
        if (color) rs += 'color:' + color + ';';
        inner += '<span style="' + rs + '">' + escapeHtml(text) + '</span>';
      }
      if (!anyText) return '';
      var prefix = '';
      if (st.bullet && st.bullet !== 'none') {
        prefix = st.bullet === 'num' ? (nextNum() + '. ') : (st.bullet + ' ');
      }
      var ps = 'margin:0;line-height:1.25;';
      if (st.algn === 'ctr') ps += 'text-align:center;';
      else if (st.algn === 'r') ps += 'text-align:right;';
      if (st.marL) ps += 'padding-left:' + (st.marL * pxPerEmu) + 'px;';
      if (st.bullet && st.bullet !== 'none') ps += 'padding-left:' + (prefix.length > 2 ? 0 : 12) + 'px;';
      return '<p style="' + ps + '">' + (prefix ? '<span style="font-size:inherit">' + escapeHtml(prefix) + '</span>' : '') + inner + '</p>';
    }

    function renderTextBox(txBody, box, kind, levels, pxPerEmu) {
      var style = 'position:absolute;left:' + (box.x * pxPerEmu) + 'px;top:' + (box.y * pxPerEmu) + 'px;' +
        'width:' + (box.cx * pxPerEmu) + 'px;height:' + (box.cy * pxPerEmu) + 'px;overflow:hidden;';
      var bodyPr = txBody.getElementsByTagName('a:bodyPr')[0];
      if (bodyPr && bodyPr.getAttribute('anchor') === 'ctr') {
        style += 'display:flex;flex-direction:column;justify-content:center;';
      }
      var paras = txBody.getElementsByTagName('a:p');
      var html = '';
      var numCounter = 0;
      for (var i = 0; i < paras.length; i++) {
        html += renderParagraph(paras[i], levels, pxPerEmu, function () {
          numCounter++;
          return numCounter;
        });
      }
      if (!html) return '';
      return '<div style="' + style + '">' + html + '</div>';
    }

    function renderPicture(pic, pxPerEmu, mediaUrl) {
      var xfrm = readXfrm(pic.getElementsByTagName('a:xfrm')[0]);
      var blip = pic.getElementsByTagName('a:blip')[0];
      if (!xfrm || !blip) return Promise.resolve('');
      var rId = blip.getAttribute('r:embed');
      return mediaUrl(rId).then(function (dataUrl) {
        if (!dataUrl) return '';
        return '<img src="' + dataUrl + '" style="position:absolute;left:' + (xfrm.x * pxPerEmu) + 'px;top:' + (xfrm.y * pxPerEmu) + 'px;width:' + (xfrm.cx * pxPerEmu) + 'px;height:' + (xfrm.cy * pxPerEmu) + 'px">';
      });
    }

    var slidePromises = [];

    var sps = doc.getElementsByTagName('p:sp');
    for (var i = 0; i < sps.length; i++) {
      var sp = sps[i];
      var xfrm = readXfrm(sp.getElementsByTagName('a:xfrm')[0]);
      var ph = sp.getElementsByTagName('p:ph')[0];
      var phType = ph ? (ph.getAttribute('type') || 'obj') : null;
      var box = xfrm || (ph ? resolvePhBox(phType, ph.getAttribute('idx')) : null);
      if (!box) continue;
      var kind = shapeKind(phType);
      var levels = chainLevels(
        defaultStyle,
        layout ? (kind === 'title' ? layout.titleLevels : layout.bodyLevels) : {},
        master ? (kind === 'title' ? master.titleLevels : master.bodyLevels) : {}
      );
      var txBody = sp.getElementsByTagName('p:txBody')[0];
      if (txBody) {
        var html = renderTextBox(txBody, box, kind, levels, pxPerEmu);
        if (html) slidePromises.push(html);
      }
    }

    var pics = doc.getElementsByTagName('p:pic');
    var picPromises = [];
    for (var p = 0; p < pics.length; p++) {
      picPromises.push(renderPicture(pics[p], pxPerEmu, mediaUrl));
    }

    return Promise.all(picPromises).then(function (picsHtml) {
      var inner = slidePromises.join('') + picsHtml.filter(Boolean).join('');
      var h = Math.round(S * slideH / slideW);
      return '<div class="mb-6">' +
        '<p class="font-mono font-bold text-xs uppercase text-gray-400 mb-1">Slide ' + num + '</p>' +
        '<div class="border border-[#E5E7EB] shadow-brutal bg-white relative overflow-hidden" style="width:100%;max-width:' + S + 'px;height:' + h + 'px">' +
        inner +
        '</div></div>';
    });
  }

  // ── Entry point: unzip, gather theme, render every slide in order ──
  window.pptxPreview = {
    parse: function (buffer) {
      return JSZip.loadAsync(buffer).then(function (zip) {
        var presXml = zip.file('ppt/presentation.xml');
        if (!presXml) throw new Error('Not a PPTX file');
        return Promise.all([presXml.async('text'), loadTheme(zip)]).then(function (res) {
          var pres = res[0];
          var theme = res[1];
          var sm = pres.match(/<p:sldSz[^>]*cx="(\d+)"[^>]*cy="(\d+)"/);
          var slideW = sm ? parseInt(sm[1], 10) : 12192000;
          var slideH = sm ? parseInt(sm[2], 10) : 6858000;
          var defaultStyle = {};
          var dm = pres.match(/<p:defaultTextStyle>[\s\S]*?<\/p:defaultTextStyle>/);
          if (dm) defaultStyle = parseStyleSet(dm[0], null);
          var slideNames = Object.keys(zip.files).filter(function (n) {
            return /^ppt\/slides\/slide\d+\.xml$/.test(n);
          }).sort(function (a, b) {
            return parseInt(a.match(/\d+/)[0], 10) - parseInt(b.match(/\d+/)[0], 10);
          });
          if (!slideNames.length) throw new Error('No slides found');
          var slidesP = slideNames.map(function (n, i) {
            var relsName = 'ppt/slides/_rels/' + n.split('/').pop() + '.rels';
            var relsFile = zip.file(relsName);
            var relsP = relsFile ? relsFile.async('text') : Promise.resolve('');
            return Promise.all([zip.files[n].async('text'), relsP]).then(function (r) {
              return renderSlide(r[0], r[1], zip, slideW, slideH, i + 1, theme, defaultStyle);
            });
          });
          return Promise.all(slidesP).then(function (slides) {
            return '<div class="space-y-6">' + slides.join('') + '</div>';
          });
        });
      });
    }
  };
})();
