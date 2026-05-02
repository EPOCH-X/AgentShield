import dynamic from "next/dynamic";

// SSR을 완전히 건너뜀 — useRouter/usePathname 컨텍스트 null 에러 방지
const IntroClient = dynamic(() => import("./IntroClient"), { ssr: false });

export default function IntroPage() {
  return <IntroClient />;
}
