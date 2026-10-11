import { redirect } from "next/navigation";
import { currentAccount } from "../../lib/session";

export default async function LabIndex() {
  if (await currentAccount()) redirect("/dashboard");
  redirect("/");
}
