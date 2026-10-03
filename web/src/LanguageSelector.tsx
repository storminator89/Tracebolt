import { ChevronDown, Languages } from 'lucide-react';
import { t, useLocale } from './i18n';
export function LanguageSelector(){const [locale,setLocale]=useLocale();return <label className="language-control"><Languages size={15} aria-hidden="true"/><select aria-label={t('Sprache')} value={locale} onChange={event=>setLocale(event.target.value==='de'?'de':'en')}><option value="en" lang="en">English</option><option value="de" lang="de">Deutsch</option></select><ChevronDown size={11} aria-hidden="true"/></label>;}
